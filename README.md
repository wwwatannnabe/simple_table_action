# simple_table_action
WBSのテーブルマッチング用のbasicfwd.c初版

### skeleton/basicfwd.c
CNF側のcプログラム

### p4_program/table_late.p4
WBS側のp4プログラム

table
- check_port()
  optionヘッダから送信先ポートを決定
- option_5000
  送信元ポートからoptionの数値(5000)を決定 \
  
action
- send_to_???
 ???番ポートに送信
- option_5000
 optionヘッダに5000と書き込み
