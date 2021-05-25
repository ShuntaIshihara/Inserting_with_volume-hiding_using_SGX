# Inserting_with_volume-hiding_using_SGX

## Enclave内でcuckoo hashing托卵操作
### 大まかな処理の流れ
cuckoo hashingテーブルと挿入するキーバリューデータをEnclave内の関数に渡して、
Enclave内で托卵操作を行う

### Enclave内関数
**start関数**
- 引数：cuckoo hashingテーブルのコピー、（暗号化された）挿入するキーバリューデータ
- 戻り値：void
- cuckoo関数に挿入するキーバリューデータを渡す
    -溢れたデータをstashに格納
- 強制的に托卵操作をする
    - ランダムにT1上のアドレスを一箇所選ぶ
    - その箇所にダミーデータを挿入する (cuckoo関数にダミーデータを渡す)
    - 溢れたデータをstashに格納
***
**cuckoo関数**
- 引数：
