





<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
  <link rel="dns-prefetch" href="https://assets-cdn.github.com">
  <link rel="dns-prefetch" href="https://avatars0.githubusercontent.com">
  <link rel="dns-prefetch" href="https://avatars1.githubusercontent.com">
  <link rel="dns-prefetch" href="https://avatars2.githubusercontent.com">
  <link rel="dns-prefetch" href="https://avatars3.githubusercontent.com">
  <link rel="dns-prefetch" href="https://github-cloud.s3.amazonaws.com">
  <link rel="dns-prefetch" href="https://user-images.githubusercontent.com/">



  <link crossorigin="anonymous" media="all" integrity="sha512-lLo2nlsdl+bHLu6PGvC2j3wfP45RnK4wKQLiPnCDcuXfU38AiD+JCdMywnF3WbJC1jaxe3lAI6AM4uJuMFBLEw==" rel="stylesheet" href="https://assets-cdn.github.com/assets/frameworks-08fc49d3bd2694c870ea23d0906f3610.css" />
  <link crossorigin="anonymous" media="all" integrity="sha512-4kfWSrzu4OShEnC5m0lqUCfKkZfG7JH0ff4wnEtubTUTZqV5pS5oUMTOvWE2DDL7ttjZ9FpnZInl/0TLO3EIiA==" rel="stylesheet" href="https://assets-cdn.github.com/assets/github-6c1d4c04bb55a87b9cb81ffdbd683662.css" />
  
  
  <link crossorigin="anonymous" media="all" integrity="sha512-PcJMPDRp7jbbEAmTk9kaL2kRQqg69QZ26WsZf07xsPyaipKsi3wVG0805PZNYXxotPDAliKKFvNSQPhD8fp1FQ==" rel="stylesheet" href="https://assets-cdn.github.com/assets/site-50c740d9290419d070dd6213a7cd03b5.css" />
  
  

  <meta name="viewport" content="width=device-width">
  




  <link rel="manifest" href="/manifest.json" crossOrigin="use-credentials">

  </head>

  <body>
  <div id="readme" class="readme blob instapaper_body">
  <article class="markdown-body entry-content" itemprop="text">
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  <p></p>
  
  
  
  
  
  
  
  <p>
  </p>
  
  
  
  
  
  
  
  
  
  
  
  <p></p>
  
  
  
  
  
  
  
  
  
  <div>

<div id="user-content-readme">
<h1><a id="user-content-estensione-di-ndpi-con-modbus" class="anchor" aria-hidden="true" href="#estensione-di-ndpi-con-modbus"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 9h1v1H4c-1.5 0-3-1.69-3-3.5S2.55 3 4 3h4c1.45 0 3 1.69 3 3.5 0 1.41-.91 2.72-2 3.25V8.59c.58-.45 1-1.27 1-2.09C10 5.22 8.98 4 8 4H4c-.98 0-2 1.22-2 2.5S3 9 4 9zm9-3h-1v1h1c1 0 2 1.22 2 2.5S13.98 12 13 12H9c-.98 0-2-1.22-2-2.5 0-.83.42-1.64 1-2.09V6.25c-1.09.53-2 1.84-2 3.25C6 11.31 7.55 13 9 13h4c1.45 0 3-1.69 3-3.5S14.5 6 13 6z"></path></svg></a><a id="user-content-estensione di ndpi con modbus" href="#Estensione di nDPI con Modbus"></a>Estensione di nDPI con Modbus</h1>
<h1><a id="user-content-operazione-preliminare-" class="anchor" aria-hidden="true" href="#operazione-preliminare-"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 9h1v1H4c-1.5 0-3-1.69-3-3.5S2.55 3 4 3h4c1.45 0 3 1.69 3 3.5 0 1.41-.91 2.72-2 3.25V8.59c.58-.45 1-1.27 1-2.09C10 5.22 8.98 4 8 4H4c-.98 0-2 1.22-2 2.5S3 9 4 9zm9-3h-1v1h1c1 0 2 1.22 2 2.5S13.98 12 13 12H9c-.98 0-2-1.22-2-2.5 0-.83.42-1.64 1-2.09V6.25c-1.09.53-2 1.84-2 3.25C6 11.31 7.55 13 9 13h4c1.45 0 3-1.69 3-3.5S14.5 6 13 6z"></path></svg></a><a id="user-content-compilazione ed esecuzione " href="#Operazione preliminare "></a>Operazione preliminare </h1>
<div><p>Scaricare nDPI dal sito ufficiale <a href="https://github.com/ntop/nDPI/">https://github.com/ntop/nDPI/</a> ed estrarre la cartella</p>
<p>Controllare se nella cartella src/lib/protocols sia presente il file modbus.c 
<p>Se è presente allora è possibile passare direttamente a Compilazione ed Esecuzione</p>
<p>Altrimenti è necessario eseguire la seguente operazione</p>
<pre>$ ./update.sh nomecartella     (es ./update.sh nDPi-dev)<p>Copia i nuovi file all'interno di nDPi </p></pre></div>


<p>  </p>
<h1><a id="user-content-compilazione-ed-esecuzione-" class="anchor" aria-hidden="true" href="#compilazione-ed-esecuzione-"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 9h1v1H4c-1.5 0-3-1.69-3-3.5S2.55 3 4 3h4c1.45 0 3 1.69 3 3.5 0 1.41-.91 2.72-2 3.25V8.59c.58-.45 1-1.27 1-2.09C10 5.22 8.98 4 8 4H4c-.98 0-2 1.22-2 2.5S3 9 4 9zm9-3h-1v1h1c1 0 2 1.22 2 2.5S13.98 12 13 12H9c-.98 0-2-1.22-2-2.5 0-.83.42-1.64 1-2.09V6.25c-1.09.53-2 1.84-2 3.25C6 11.31 7.55 13 9 13h4c1.45 0 3-1.69 3-3.5S14.5 6 13 6z"></path></svg></a><a id="user-content-compilazione ed esecuzione " href="#Compilazione ed Esecuzione "></a>Compilazione ed Esecuzione </h1>
<div><pre>$ ./run.sh nomecartella<p>esegue tutti i comandi tipici di nDPI presi dal sito <a href="https://github.com/ntop/nDPI/">https://github.com/ntop/nDPI/</a> </p></pre></div>
<p>  </p>
<p>  
</p><h1><a id="user-content-modbus-check" class="anchor" aria-hidden="true" href="#modbus-check"><svg class="octicon octicon-link" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 9h1v1H4c-1.5 0-3-1.69-3-3.5S2.55 3 4 3h4c1.45 0 3 1.69 3 3.5 0 1.41-.91 2.72-2 3.25V8.59c.58-.45 1-1.27 1-2.09C10 5.22 8.98 4 8 4H4c-.98 0-2 1.22-2 2.5S3 9 4 9zm9-3h-1v1h1c1 0 2 1.22 2 2.5S13.98 12 13 12H9c-.98 0-2-1.22-2-2.5 0-.83.42-1.64 1-2.09V6.25c-1.09.53-2 1.84-2 3.25C6 11.31 7.55 13 9 13h4c1.45 0 3-1.69 3-3.5S14.5 6 13 6z"></path></svg></a><a id="user-content-modbus check" href="#Modbus Check"></a>Modbus Check</h1>
<div><pre>$ ./Modbuscheck.sh nomecartella<p>visualizza a video il contenuto del file Modbus.pcap.out ed esegue nDpiReader con il pcap di Modbus</p></pre></div>
<p>  </p>



  

 


  </body>
</html>

