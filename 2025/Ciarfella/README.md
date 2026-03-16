# App Fingerprinting

| Name        | Email                   |
|-------------|-------------------------|
|Ciarfella Marco|m.ciarfella@studenti.unipi.it|
|||

## Obiettivo
Il focus di questo progetto è riconoscere e confrontare le impronte TLS lasciate da certe App per mobile.

## Procedimento
1. È stato connesso un PC (MacBook) al router di casa via cavo Ethernet
2. Usato il PC come hotspot
3. Connesso un telefono via Wi-fi al PC


Sono state analizzate 7 App per mobile tra cui:
- Amazon
- Instagram
- Youtube
- TikTok
- Subito
- TicketOne
- Whatsapp

Dopo aver raccolto e salvato i 7 file .pcap, essi sono stati analizzati utilizzando _ndpiReader_ contenuto in nDPI (https://github.com/ntop/nDPI)

## 📍Resoconto
Le principali caratteristiche delle conversazioni TCP sono così riassunte:

||  <center>Protocollo di Cifratura</center> | <center> TCP Fingerprint</center> |
| ------------ | ----------------------- | ----------------|
| __Subito__   | <center>TLS</center> | <center>194_64_65535_d29295416479/macOS</center> |
| __Whatsapp__ | <center>TLS.Whatsapp</center> | <center>194_64_65535_d29295416479/macOS</center> |
| __TicketOne__| <center>TLS</center> | <center>194_64_65535_d29295416479/macOS</center> | 
| __Instagram__| <center>TLS.FacebookMessenger</center> | <center>194_64_65535_d29295416479/macOS</center> |
| __TikTok__   | <center>TLS.TikTok</center> | <center>194_64_65535_d29295416479/macOS</center> |
| __Youtube__  | <center>TLS.Youtube</center> | <center>194_64_65535_d29295416479/macOS</center> |
| __Amazon__   | <center>TLS.Amazon</center> | <center>194_64_65535_d29295416479/macOS</center> |

<br><br>

Nella seguente tabella le combinazioni tra JA4 e JA3S osservate 

||  <center>JA4</center> | <center>JA3S</center> |
| ------------ | ----------------------- | ----------------|
| __Subito__  | [t13d2013h2_a09f3c656075_7f0f34a4126d]|[15af977ce25de452b96affa2addb1036]| 
| __Subito__  | [t13d2013ht_a09f3c656075_7f0f34a4126d] | [15af977ce25de452b96affa2addb1036] |
| __Whatsapp__ | [t13d2013h2_a09f3c656075_7f0f34a4126d] | [475c9302dc42b2751db9edcac3b74891] |
| __TicketOne__| [t13d2013h2_a09f3c656075_7f0f34a4126d] | [15af977ce25de452b96affa2addb1036] |
| __Instagram__| [t00d030800_55b375c5d22e_566d5108064c] | [fcb2d4d0991292272fcb1e464eedfd43] |
| __TikTok__  | [t13d181100_e8a523a41297_ef7df7f74e48] | [15af977ce25de452b96affa2addb1036] |
| __TikTok__  | [t13d181100_e8a523a41297_ef7df7f74e48] | [f4febc55ea12b31ae17cfb7e614afda8] |
| __TikTok__  | [t13d181100_e8a523a41297_d5fe2c511efa] | [2253c82f03b621c5144709b393fde2c9] |
| __TikTok__  | [t13d1516h2_8daaf6152771_e5627efa2ab1] | [15af977ce25de452b96affa2addb1036] |
| __TikTok__  | [t13d1516h2_8daaf6152771_e5627efa2ab1] | [eb1d94daa7e0344597e756a1fb6e7054] |
| __TikTok__  | [t13d1516h2_8daaf6152771_e5627efa2ab1] | [f4febc55ea12b31ae17cfb7e614afda8] |
| __TikTok__  | [t13d1516ht_8daaf6152771_e5627efa2ab1] | [15af977ce25de452b96affa2addb1036] |
| __Youtube__ | [t13d0912h2_f91f431d341e_ef7df7f74e48] | [eb1d94daa7e0344597e756a1fb6e7054] |
| __Youtube__ | [t13d1313h2_f57a46bbacb6_7f0f34a4126d] | [907bf3ecef1c987c889946b737b43de8] |
| __Youtube__ | [t13d0913h2_f91f431d341e_02c8e53ee398] | [2b0648ab686ee45e0e7c35fcfb0eea7e] |
| __Amazon__  | [t13d1313ht_f57a46bbacb6_7f0f34a4126d] | [f4febc55ea12b31ae17cfb7e614afda8] |
| __Amazon__  | [t13d1313ht_f57a46bbacb6_7f0f34a4126d] | [15af977ce25de452b96affa2addb1036] |
| __Amazon__  | [t13d1313h2_f57a46bbacb6_7f0f34a4126d] | [f4febc55ea12b31ae17cfb7e614afda8] |
| __Amazon__  | [t13d1313h2_f57a46bbacb6_7f0f34a4126d] | [15af977ce25de452b96affa2addb1036] |
| __Amazon__  | [t13d1313h2_f57a46bbacb6_7f0f34a4126d] | [cabca0e45d1843a8873f229da4a3323f] |
| __Amazon__  | [t13d1313h2_f57a46bbacb6_7f0f34a4126d] | [50a9e7b112931e541503e8a2499252b9] |
| __Amazon__  | [t12d220700_0d4ca5d4ec72_3304d8368043] | [e36e593c5f33a620e2c9d3801f61be4a] |