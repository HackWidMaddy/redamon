// nwlab first-party bundle (lab fixture).
// js-only.v2.api.nwlab.test exists only here: JS recon must inject it into a
// *.api.nwlab.test group. cdn.nwlab.test is a sibling outside that scan root and
// must not be injected into it.
(function () {
  var API_V2 = "https://js-only.v2.api.nwlab.test/x";
  var CDN_LIB = "https://cdn.nwlab.test/lib.js";

  function loadLib() {
    var s = document.createElement("script");
    s.src = CDN_LIB;
    document.head.appendChild(s);
  }

  function ping() {
    return fetch(API_V2, { credentials: "omit" }).then(function (r) {
      return r.status;
    });
  }

  window.nwlab = { loadLib: loadLib, ping: ping };
})();
