#!/bin/bash
WD=$PWD
sudo crontab -l >> mycron
usage() { echo "Usage: $0 [-r <number_of_repetition>] [-f <output_file>] [-i <device>]" 1>&2; exit 1; }
echo "PATH=/sbin:/bin:/usr/bin" >> mycron

if [ "$#" -eq 0 ]
then
    echo "* * * * * cd $WD && ./harper -r2" >> mycron
else
    while getopts ":r:f:i:" o; do
    case "${o}" in
        r)
            r=${OPTARG}
            ropt="-r $r"
	    ;;
        f)
            f=${OPTARG}
            fopt=">> $f"
            ;;
        i)
            i=${OPTARG}
            iopt="-i $i"
            ;;
        *)
            usage
            ;;
    esac
    done
    if [ ! -z "$r" ];then
     echo "* * * * * cd $WD && (./harper $ropt $iopt $fopt)" >> mycron
    else
     echo "* * * * * cd $WD && (./harper -r2 $iopt $fopt)" >> mycron
    fi
fi
shift "$((OPTIND-1))"


sudo crontab mycron
rm mycron
