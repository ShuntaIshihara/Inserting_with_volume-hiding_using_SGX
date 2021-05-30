# Inserting_with_volume-hiding_using_SGX

## Enclave内でcuckoo hashing托卵操作
### 大まかな処理の流れ
cuckoo hashingテーブルと挿入するキーバリューデータをEnclave内の関数に渡して、
Enclave内で托卵操作を行う

### Enclave内関数
**start関数**
- 引数：（暗号化された）挿入するキーバリューデータ、cuckoo hashingテーブルのコピー、hash関数のseed
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
- 引数：キーバリューデータ、cuckoo hashingテーブル、hash関数のseed、tableID、再帰回数カウント、再帰回数上限
- 戻り値：溢れたデータ
- if 再帰回数が上限に達した場合：終了
- key値の複合
- keyからT1とT2のハッシュ値を計算
- 入れ替え操作
    - 追い出されたデータをcuckoo関数に渡す

## 疑問点
- stashに入れるデータをクライアントに返す時，ダミーデータも混ぜたほうがいいのか
