# Inserting_with_volume-hiding_using_SGX

## Enclave内でcuckoo hashing托卵操作
### 大まかな処理の流れ
cuckoo hashingテーブルと挿入するキーバリューデータをEnclave内の関数に渡して、
Enclave内で托卵操作を行う

### Enclave内関数
**start関数**
- 引数：（暗号化された）挿入するキーバリューデータ、cuckoo hashingテーブルのコピー、テーブルサイズ
- 戻り値型：int
- cuckoo関数に挿入するキーバリューデータを渡す
    - 溢れたデータをstashに格納
- 強制的に托卵操作をする
    - ランダムにT1上のアドレスを一箇所選ぶ
    - その箇所にダミーデータを挿入する (cuckoo関数にダミーデータを渡す)
    - 溢れたデータをstashに格納
- OCALLでstashをEnclave外に返す
---
**cuckoo関数**
- 引数：キーバリューデータ、cuckoo hashingテーブル、テーブルサイズ、tableID、再帰回数カウント、再帰回数上限
- 戻り値：溢れたデータ
- if 再帰回数が上限に達した場合：終了
- key値の複合
- keyからT1とT2のハッシュ値を計算
- 入れ替え操作
    - 追い出されたデータをcuckoo関数に渡す

### cuckoo hashingの動作のテスト（SGXなし）
```zsh
===Before===
T1 = {dummy_0, dummy_1, dummy_2, dummy_3, dummy_4, dummy_5, dummy_6, dummy_7, dummy_8, dummy_9}
T2 = {dummy_01, dummy_11, dummy_21, dummy_31, dummy_41, dummy_51, dummy_61, dummy_71, dummy_81, dummy_91}
stash = {}
===After===
T1 = {dummy_1217561367, dummy_81, dummy_3945025673, dummy_4, dummy_1699515842, dummy_9, dummy_1620770490, key0, dummy_31, dummy_2439117702}
T2 = {dummy_21, dummy_2, key6, key7, key4, dummy_51, dummy_11, key9, dummy_546934652, dummy_615570064}
stash = {key1, key2, key3, key5, key8, }
```
## 疑問点
- stashに入れるデータをクライアントに返す時，ダミーデータも混ぜたほうがいいのか
