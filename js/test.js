( () => {
    class e {
        static Disabled = new e("disabled");
        static Analyze = new e("analyze");
        static Block = new e("block");
        static Repair = new e("repair");
        constructor(e) {
            this.name = e
        }
    }
    let n = new URL(window.location.href);
    n = n.hostname.replace("www.", "");
    const t = ["google.com"];
    function o(n) {
        let t = new XMLHttpRequest;
        t.open("GET", window.location.href, !1),
        t.onerror = function() {
            document.documentElement.innerHTML = "Error getting Page, try desabling the extension and reload the page"
        }
        ,
        t.onload = async function() {
            const t = document.implementation.createHTMLDocument("");
            t.documentElement.innerHTML = this.responseText;
            const o = document.importNode(t.documentElement, !0)
              , r = o.querySelectorAll("script");
            let s = [];
            for (let e = 0; e < r.length; ++e) {
                const n = r[e];
                if (n.src) {
                    const e = c({
                        src: n.src,
                        type: "processScript"
                    });
                    s.push(e)
                } else if (n.innerHTML) {
                    const e = c({
                        script: n.innerHTML,
                        type: "processScript"
                    });
                    s.push(e)
                }
            }
            const i = await Promise.all(s);
            let l = 0
              , a = [];
            for (let t = 0; t < i.length; t++) {
                const o = r[t]
                  , c = i[t];
                if (c) {
                    l++;
                    for (let e = 0; e < c.foundVulnerabilities.length; e++) {
                        const n = c.foundVulnerabilities[e];
                        n.src = o.src ?? `inline script ${e}`,
                        a.push(n)
                    }
                    n != e.Analyze.name && (n == e.Block.name ? o.parentNode.removeChild(o) : (o.removeAttribute("src"),
                    o.innerHTML = c.output))
                }
            }
            if (chrome.runtime.sendMessage({
                vulnerableScriptsCount: l,
                processedScriptsCount: i.length,
                vulnerabilities: a,
                url: location.href,
                type: "result"
            }, ( () => {}
            )),
            n != e.Analyze.name) {
                document.replaceChild(o, document.documentElement),
                delete t;
                const e = document.createElement("script");
                e.src = chrome.runtime.getURL("evaluate.js"),
                e.setAttribute("ignore", "true"),
                document.documentElement.appendChild(e)
            }
        }
        ,
        t.send()
    }
    function c(e) {
        return new Promise(( (n, t) => {
            chrome.runtime.sendMessage(e, (e => {
                n(e)
            }
            ))
        }
        ))
    }
    chrome.storage.sync.get("js_vulnerability_detector__mode", (function(c) {
        let r = c.js_vulnerability_detector__mode;
        const s = null != r ? new e(r) : e.Analyze;
        switch (s.name != e.Disabled.name && t.includes(n) && (s = e.Analyze),
        s.name) {
        case e.Disabled.name:
            break;
        case e.Analyze.name:
            o(e.Analyze.name);
            break;
        case e.Block.name:
        case e.Repair.name:
            window.stop(),
            document.documentElement.innerHTML = "Reloading Page...",
            o(s.name)
        }
    }
    ))
}
)();
