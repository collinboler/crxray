chrome.runtime.sendMessage({ type: 'PING' }, (response) => {
  document.title = 'popupGotResponse:' + (response && response.type === 'PONG');
});
