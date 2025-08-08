const MODULE = "YouTubeUnstable";
const base = Module.findBaseAddress(MODULE);

function jsStringToNative(str) {
  // convert a JavaScript string to a char* buffer
  // make sure string is ASCII only so we don't have to deal with length issues related to UTF-8
  const vals = [];
  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    if (charCode < 0 || charCode > 255) {
      throw new Error("Prefix contains non-ASCII character at index " + i);
    }
    vals.push(str.charCodeAt(i));
  }

  vals.push(0); // null terminator

  const tmpBuf = Memory.alloc(vals.length);
  Memory.writeByteArray(tmpBuf, vals);
  return tmpBuf;
}

const insertPtr = Module.findExportByName(
  "libc++.1.dylib",
  "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm"
);
const insertFn = new NativeFunction(insertPtr, "pointer", [
  "pointer",  // std::string this
  "ulong",  // size_t pos
  "pointer",  // const char* s
  "ulong",  // size_t n
]);

function prepend(strPtr, prefix) {
  const tmpBuf = jsStringToNative(prefix);
  insertFn(strPtr, 0, tmpBuf, prefix.length);
}

function readStdString(str) {
  // std::string layout:
  // short strings just have the last byte as length, rest is for data
  // long strings:
  // 0x00: data pointer
  // 0x08: length
  // 0x0c: capacity (upper bit set to 1)

  const capacity = str.add(16).readU64();
  const topBit = capacity.shr(63);
  if (topBit.toNumber() !== 0) {
    // long string
    const chars = str.readPointer();
    const length = str.add(8).readU32();

    const res = chars.readUtf8String(length);
    return { length, capacity: capacity.xor(uint64(1).shl(63)), res };
  } else {
    // short string optimization
    // length is just the upper byte
    const length = capacity.shr(64 - 8);
    const chars = str.readUtf8String(length);
    return { length, capacity: length, res: chars };
  }
}

// unused for now, but useful for debugging by modifying existing JS.
const replacePtr = Module.findExportByName(
  "libc++.1.dylib",
  "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7replaceEmmPKc"
);
const replaceFn = new NativeFunction(replacePtr, "pointer", [
  "pointer",  // std::string this
  "ulong",  // size_t pos
  "ulong",  // size_t len
  "pointer",  // const char* s
]);

function replace(str, substr, newStr) {
  // replace a substring in a std::string with a new string
  // replaces the first occurrence of substr with newStr only
  const strData = readStdString(str);
  // find first occurrence of substr in strData.res
  const index = strData.res.indexOf(substr);
  if (index === -1) {
    return false; // substring not found, nothing to replace
  }

  const tmpBuf = jsStringToNative(newStr);

  replaceFn(
    str,
    index,  // position to start replacing
    substr.length,  // length of the substring to replace
    tmpBuf  // new string to insert
  );
  return true;
}

// Add TizenTube script to the page. Don't inject more than once.
//
// Restore 4k support by hooking window.MediaSource.isTypeSupported to remove the height/width parameters.
// I am not actually sure why this works since isTypeSupported still returns false for VP09 codecs.
// YouTube does detect spoofing by checking nonsensical values for height/width so maybe that affects something?
// HDR still does not work, but at least 4k works now.
const injectedContent = `
(function () {
if (document.mutube) return;
document.mutube = true;

// Load TizenTube script first
var script = document.createElement('script');
script.src = "https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js";
script.async = true;
document.head.appendChild(script);

// Load HLS.js for premium quality streaming
var hlsScript = document.createElement('script');
hlsScript.src = "https://cdn.jsdelivr.net/npm/hls.js@1";
hlsScript.async = true;
document.head.appendChild(hlsScript);

// 4K support - remove width/height parameters from MediaSource queries
const originalIsTypeSupported = window.MediaSource.isTypeSupported.bind(window.MediaSource);

window.MediaSource.isTypeSupported = function(mimeType) {
  const parts = mimeType
    .split(';')
    .map(part => part.trim())
    .filter(part => part);

  const filtered = parts.filter(part => {
    return !(part.startsWith('width=') || part.startsWith('height='));
  });

  const cleaned = filtered.join('; ');
  return originalIsTypeSupported(cleaned);
};

// HLS Premium Quality
const nativeJSONParse = window.JSON.parse;

function getYtcfgValue(name) {
  return window.ytcfg && window.ytcfg.get ? window.ytcfg.get(name) : undefined;
}

function getCurrentVideoId() {
  const search = window.location.search;
  if (search) {
    const match = search.match(/[?&]v=([^&]+)/);
    if (match) return match[1];
  }
  return (getYtcfgValue('PLAYER_VARS') && getYtcfgValue('PLAYER_VARS').video_id);
}


window.hlsManifestData = {
  url: null,
  enabled: false,
  player: null,
  currentVideoId: null,
  originalSrc: null
};


window.JSON.parse = function() {
  const data = nativeJSONParse.apply(this, arguments);
  
  if (data && typeof data === 'object') {
    if (data.videoDetails && data.playabilityStatus) {
      return interceptPlayerResponse(data);
    }
    
    if (data.playerResponse && data.playerResponse.videoDetails && data.playerResponse.playabilityStatus) {
      data.playerResponse = interceptPlayerResponse(data.playerResponse);
    }
  }
  
  return data;
};

function interceptPlayerResponse(originalResponse) {
  const videoId = (originalResponse.videoDetails && originalResponse.videoDetails.videoId) || getCurrentVideoId();
  if (!videoId || !originalResponse.streamingData) return originalResponse;
  
  window.hlsManifestData.currentVideoId = videoId;
  
  if (originalResponse.streamingData.hlsManifestUrl) {
    window.hlsManifestData.url = originalResponse.streamingData.hlsManifestUrl;
    window.hlsDebugInfo = 'Found native HLS manifest';
  } else {
    const adaptiveFormats = originalResponse.streamingData.adaptiveFormats || [];
    const formats = originalResponse.streamingData.formats || [];
    
    const allFormats = [...formats, ...adaptiveFormats];
    const videoFormats = allFormats.filter(format => 
      format.url && format.mimeType && format.mimeType.includes('video') && 
      (format.quality || format.qualityLabel)
    );
    
    if (videoFormats.length > 0) {
      const sortedFormats = videoFormats.sort((a, b) => {
        const bitrateA = parseInt(a.bitrate) || 0;
        const bitrateB = parseInt(b.bitrate) || 0;
        if (bitrateA !== bitrateB) return bitrateB - bitrateA;
        
        const heightA = parseInt(a.height) || parseInt(a.qualityLabel) || 0;
        const heightB = parseInt(b.height) || parseInt(b.qualityLabel) || 0;
        return heightB - heightA;
      });
      
      const bestFormat = sortedFormats[0];
      const bestBitrate = parseInt(bestFormat.bitrate) || 0;
      const bestHeight = parseInt(bestFormat.height) || parseInt(bestFormat.qualityLabel) || 0;
      
      const isPremium = bestHeight >= 1080 || bestBitrate >= 5000000;
      
      if (isPremium) {
        window.hlsManifestData.url = bestFormat.url;
        const bitrateInfo = bestBitrate > 0 ? ' @' + Math.round(bestBitrate/1000000) + 'Mbps' : '';
        window.hlsDebugInfo = 'Premium: ' + (bestFormat.qualityLabel || bestFormat.quality) + bitrateInfo;
      } else {
        const bitrateInfo = bestBitrate > 0 ? ' @' + Math.round(bestBitrate/1000000) + 'Mbps' : '';
        window.hlsDebugInfo = 'Standard: ' + (bestFormat.qualityLabel || bestFormat.quality) + bitrateInfo;
      }
    } else {
      window.hlsDebugInfo = 'No video formats found';
    }
  }
  
  return originalResponse;
}

function enableHLSPlayback() {
  if (!window.hlsManifestData.url) {
    return false;
  }

  const video = document.querySelector('video');
  if (!video) return false;

  if (!window.hlsManifestData.originalSrc) {
    window.hlsManifestData.originalSrc = video.src;
  }

  const currentTime = video.currentTime;
  const wasPaused = video.paused;

  // Check if URL is an HLS manifest (.m3u8) or a direct stream
  if (window.hlsManifestData.url.includes('.m3u8')) {
    if (!window.Hls || !window.Hls.isSupported()) {
      return false;
    }

    if (window.hlsManifestData.player) {
      window.hlsManifestData.player.destroy();
    }

    window.hlsManifestData.player = new window.Hls({
      debug: false,
      abrEwmaDefaultEstimate: 5000000
    });

    window.hlsManifestData.player.loadSource(window.hlsManifestData.url);
    window.hlsManifestData.player.attachMedia(video);

    window.hlsManifestData.player.on(window.Hls.Events.MANIFEST_PARSED, function() {
      video.currentTime = currentTime;
      if (!wasPaused) {
        video.play();
      }
    });

    window.hlsManifestData.player.on(window.Hls.Events.ERROR, function(event, data) {
      if (data.fatal) {
        disableHLSPlayback();
        window.hlsManifestData.enabled = false;
      }
    });
  } else {
    video.addEventListener('error', function(e) {
      window.hlsManifestData.enabled = false;
      if (window.hlsManifestData.originalSrc) {
        video.src = window.hlsManifestData.originalSrc;
        video.load();
      }
      showYouTubeTVToast('Stream Error', 'Direct stream failed to load');
    }, { once: true });
    
    video.addEventListener('loadedmetadata', function() {
      video.currentTime = currentTime;
      if (!wasPaused) {
        video.play();
      }
    }, { once: true });
    
    video.src = window.hlsManifestData.url;
    video.load();
  }
  
  return true;
}

function disableHLSPlayback() {
  const video = document.querySelector('video');
  const currentTime = video ? video.currentTime : 0;
  const wasPaused = video ? video.paused : true;

  if (window.hlsManifestData.player) {
    window.hlsManifestData.player.destroy();
    window.hlsManifestData.player = null;
  }

  if (video && window.hlsManifestData.originalSrc) {
    // Restore original source
    video.src = window.hlsManifestData.originalSrc;
    video.load();
    
    video.addEventListener('loadedmetadata', function() {
      if (currentTime > 0) {
        video.currentTime = currentTime;
      }
      if (!wasPaused) {
        video.play();
      }
    }, { once: true });
  }
}

function toggleHLS() {
  if (window.hlsManifestData.enabled) {
    window.hlsManifestData.enabled = false;
    disableHLSPlayback();
    showYouTubeTVToast('HLS Manifest Disabled', '');
  } else {
    if (window.hlsManifestData.url) {
      if (enableHLSPlayback()) {
        window.hlsManifestData.enabled = true;
        showYouTubeTVToast('HLS Manifest Enabled', '');
      } else {
        showYouTubeTVToast('HLS Manifest Failed', '');
      }
    } else {
      showYouTubeTVToast('No HLS Available', window.hlsDebugInfo || '');
    }
  }
}

// YouTube TV toast notification function
function showYouTubeTVToast(title, subtitle) {
  const toastCommand = {
    openPopupAction: {
      popupType: 'TOAST',
      popup: {
        overlayToastRenderer: {
          title: { simpleText: title },
          subtitle: { simpleText: subtitle }
        }
      }
    }
  };
  
  if (window._yttv) {
    for (let key in window._yttv) {
      if (window._yttv[key] && window._yttv[key].instance && window._yttv[key].instance.resolveCommand) {
        window._yttv[key].instance.resolveCommand(toastCommand, {});
        return;
      }
    }
  }
}

// Wait for TizenTube to load, then integrate HLS toggle
function waitForTizenTube() {
  if (window._yttv) {
    for (let key in window._yttv) {
      if (window._yttv[key] && window._yttv[key].instance && window._yttv[key].instance.resolveCommand) {
        const originalResolve = window._yttv[key].instance.resolveCommand;
        
        window._yttv[key].instance.resolveCommand = function(command, options) {
          if (command.openPopupAction && command.openPopupAction.uniqueId === 'playback-settings') {
            const items = command.openPopupAction.popup.overlaySectionRenderer.overlay.overlayTwoPanelRenderer.actionPanel.overlayPanelRenderer.content.overlayPanelItemListRenderer.items;
            
            for (let i = 0; i < items.length; i++) {
              const item = items[i];
              const renderer = item.compactLinkRenderer;
              
              if (renderer && renderer.icon && renderer.icon.iconType === 'SLOW_MOTION_VIDEO') {
                const hlsToggle = {
                  compactLinkRenderer: {
                    title: { simpleText: 'HLS Manifest' },
                    subtitle: { simpleText: 'Extremely experimental. Broken.' },
                    serviceEndpoint: {
                      signalAction: {
                        customAction: {
                          action: 'HLS_TOGGLE'
                        }
                      }
                    }
                  }
                };
                
                items.splice(i + 1, 0, hlsToggle);
                break;
              }
            }
          }
          
          if (command.signalAction && command.signalAction.customAction && command.signalAction.customAction.action === 'HLS_TOGGLE') {
            toggleHLS();
            return null;
          }
          
          return originalResolve.call(this, command, options);
        };
        
        // Show ready message
        setTimeout(function() {
          showYouTubeTVToast('HLS Manifest Ready', 'Toggle in player settings menu');
        }, 3000);
        
        return;
      }
    }
  }
  
  // Retry if TizenTube not ready
  setTimeout(waitForTizenTube, 2000);
}

// Start waiting for TizenTube
setTimeout(waitForTizenTube, 5000);

})();

`;

// HTMLScriptElement::Execute
// https://cobalt.googlesource.com/cobalt/+/19.lts.1+/src/cobalt/dom/html_script_element.cc#593
Interceptor.attach(base.add(0xed4a30), {
  onEnter(args) {
    const content = args[1];
    if (readStdString(content).res.includes("yttv")) {
      prepend(content, injectedContent);
    }
  },
});

// DirectiveList::AddDirective
// https://cobalt.googlesource.com/cobalt/+/19.lts.1+/src/cobalt/csp/directive_list.cc#834
Interceptor.attach(base.add(0x152ccc8), {
  onEnter(args) {
    prepend(
      args[2],
      "sponsorblock.inf.re sponsor.ajay.app dearrow-thumb.ajay.app cdn.jsdelivr.net www.youtube.com youtube.com googlevideo.com *.googlevideo.com ytimg.com *.ytimg.com "
    );
  },
});
