package challenges

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.omada.cafe/atf/waf/internal/errorpage"
	"git.omada.cafe/atf/waf/internal/store"
	"git.omada.cafe/atf/waf/internal/token"
)

type JSHandler struct {
	store      *store.Store
	tokenMgr   *token.Manager
	nonceTTL   time.Duration
	difficulty int
	basePath   string
	log        *slog.Logger
}

func NewJSHandler(s *store.Store, tm *token.Manager, nonceTTL time.Duration, difficulty int, basePath string, log *slog.Logger) *JSHandler {
	return &JSHandler{
		store:      s,
		tokenMgr:   tm,
		nonceTTL:   nonceTTL,
		difficulty: difficulty,
		basePath:   strings.TrimRight(basePath, "/"),
		log:        log,
	}
}

func (h *JSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serve(w, r)
	case http.MethodPost:
		h.verify(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *JSHandler) serve(w http.ResponseWriter, r *http.Request) {
	ip := extractClientIP(r)
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	nonce := randomHexStr(16)
	h.store.Set("js:"+nonce, ip, h.nonceTTL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, jsChallengePage(nonce, h.difficulty, redirect, h.basePath))
	h.log.Debug("js: challenge served", "ip", ip)
}

func (h *JSHandler) verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	nonce := r.FormValue("nonce")
	answer := r.FormValue("answer")
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}
	ip := extractClientIP(r)

	storedIP, ok := h.store.Get("js:" + nonce)
	if !ok {
		http.Error(w, "Challenge expired — reload", http.StatusBadRequest)
		return
	}
	if storedIP.(string) != ip {
		errorpage.Write(w, http.StatusForbidden)
		return
	}
	h.store.Delete("js:" + nonce)

	hash := sha256.Sum256([]byte(nonce + answer))
	if !meetsHashDifficulty(hash[:], h.difficulty) {
		h.log.Warn("js: invalid solution", "ip", ip)
		errorpage.Write(w, http.StatusForbidden)
		return
	}

	tok := h.tokenMgr.Issue(ip)
	secure := r.Header.Get("X-Forwarded-Proto") == "https"
	w.Header().Set("Set-Cookie", token.CookieHeader(tok, h.tokenMgr.TTL(), secure))
	h.log.Info("js: challenge passed — token issued", "ip", ip)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func jsChallengePage(nonce string, difficulty int, redirect, basePath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser…</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html{width:100%%;background:#fff;color:#000;font-family:"Noto Serif","Source Serif",Times New Roman,serif;line-height:1.75}
html,body{min-height:100vh}
body{display:flex;margin:0 auto;max-width:83vw;flex-wrap:wrap;flex-direction:column;justify-content:space-between}
header{margin:10vh 0 0;padding-bottom:1em;border-bottom:5px solid #328c60}
header a{font-size:1.5em;font-weight:bold;color:#000;text-decoration:none}
main{display:flex;margin:1em auto;min-width:70vw;flex-wrap:wrap;flex-direction:column;padding:1em}
h1{line-height:1.5;font-size:1.625em;margin-top:1em;margin-bottom:.5em}
p{margin:.5em 0}
a{color:#36c}
em,footer{color:#777;font-style:normal}
footer{margin:0 0 10vh;padding-top:1em;border-top:1px solid #eaecf0;font-size:.9em}
.prog{font-family:monospace;color:#328c60;font-size:.9em}
.spin{display:inline-block;width:40px;height:40px;border:4px solid #eee;border-top-color:#328c60;border-radius:50%%;animation:sp .8s linear infinite;margin:1em 0}
@keyframes sp{to{transform:rotate(360deg)}}
noscript p{color:#c00;margin-top:1em}
@media(prefers-color-scheme:dark){html{background:#121212;color:#e0e0e0}header{border-bottom-color:#2d7353}header a{color:#e0e0e0}footer{border-top-color:#333;color:#aaa}}
</style>
</head>
<body>
<header><a href="/">Checking your browser</a></header>
<main>
  <div class="spin" id="spin"></div>
  <h1>Just a moment…<em> (JS challenge)</em></h1>
  <p>Completing a brief proof-of-work to verify you are human.</p>
  <p class="prog" id="prog">Initialising…</p>
  <noscript><p>JavaScript is disabled. <a href="%s/css?redirect=%s">Use the no-JS challenge.</a></p></noscript>
</main>
<footer><p>Protected by <a href="https://git.omada.cafe/atf/waf" rel="noopener">WAF</a></p></footer>
<script>
"use strict";
(function(){
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
       0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
       0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
       0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
       0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
       0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
       0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
       0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function rr(v,a){return(v>>>a)|(v<<(32-a))}
function sha256hex(msg){
  var m=unescape(encodeURIComponent(msg)),l=m.length,i;
  var b=[];for(i=0;i<l;i++)b[i>>2]|=(m.charCodeAt(i)&0xff)<<(24-(i%%4)*8);
  b[l>>2]|=0x80<<(24-(l%%4)*8);b[((l+64>>6)<<4)+15]=l*8;
  var W=new Array(64),H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  for(var j=0;j<b.length;j+=16){
    var a=H[0],bv=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(i=0;i<64;i++){
      if(i<16)W[i]=b[j+i]|0;
      else W[i]=(rr(W[i-2],17)^rr(W[i-2],19)^(W[i-2]>>>10))+(W[i-7]|0)+(rr(W[i-15],7)^rr(W[i-15],18)^(W[i-15]>>>3))+(W[i-16]|0)|0;
      var t1=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[i]+W[i]|0;
      var t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&bv)^(a&c)^(bv&c))|0;
      h=g;g=f;f=e;e=d+t1|0;d=c;c=bv;bv=a;a=t1+t2|0;
    }
    H[0]=a+H[0]|0;H[1]=bv+H[1]|0;H[2]=c+H[2]|0;H[3]=d+H[3]|0;
    H[4]=e+H[4]|0;H[5]=f+H[5]|0;H[6]=g+H[6]|0;H[7]=h+H[7]|0;
  }
  var hex='';for(i=0;i<8;i++){var v=H[i];for(var k=3;k>=0;k--)hex+=((v>>(k*8))&0xff).toString(16).padStart(2,'0');}
  return hex;
}
function zeroBits(h){var bits=0;for(var i=0;i<h.length;i++){var n=parseInt(h[i],16);if(n===0){bits+=4;}else{if(n<2)bits+=3;else if(n<4)bits+=2;else if(n<8)bits+=1;break;}}return bits;}
var nonce='%s',difficulty=%d,redirect='%s',base='%s';
var prog=document.getElementById('prog'),counter=0,batch=2000;
function work(){
  for(var end=counter+batch;counter<end;counter++){
    if(zeroBits(sha256hex(nonce+String(counter)))>=difficulty){
      prog.textContent='Verified! Redirecting…';
      var f=document.createElement('form');f.method='POST';f.action=base+'/verify-js';
      [['nonce',nonce],['answer',String(counter)],['redirect',redirect]].forEach(function(p){
        var i=document.createElement('input');i.type='hidden';i.name=p[0];i.value=p[1];f.appendChild(i);
      });
      document.body.appendChild(f);f.submit();return;
    }
  }
  if(counter%%50000===0)prog.textContent='Checked '+counter.toLocaleString()+' candidates…';
  setTimeout(work,0);
}
setTimeout(work,50);
})();
</script>
</body></html>`,
		basePath, urlPercentEncode(redirect),
		nonce, difficulty, redirect, basePath)
}
