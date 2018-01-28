input{
2 udp{
3 port => 25826
4 buffer_size => 1452
5 codec => collectd()
6 }
7 }
8 output{
9 elasticsearch{
10 template_overwrite => true
11 }
12 }
