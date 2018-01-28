#!/bin/bash
jobname=Monitoraggio_in_pratica.tex

latex $jobname 
makeglossaries ${jobname%.tex}
latex $jobname
makeglossaries ${jobname%.tex}
latex $jobname

