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

### cuckoo hashingの動作のテスト（stashなし）
{(key_0, value_0), (key_1, value_1), ... , (key_9, value_9)}の10個のデータを挿入テスト
```bash
T1 = {(dummy_0, dummy_0), (dummy_1, dummy_1), (dummy_2, dummy_2), (dummy_3, dummy_3), (dummy_4, dummy_4), (dummy_5, dummy_5), (dummy_6, dummy_6), (dummy_7, dummy_7), (dummy_8, dummy_8), (dummy_9, dummy_9)}
T2 = {(dummy_00, dummy_00), (dummy_11, dummy_11), (dummy_22, dummy_22), (dummy_33, dummy_33), (dummy_44, dummy_44), (dummy_55, dummy_55), (dummy_66, dummy_66), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_99, dummy_99)}

-----------------------------------------
Insert data (key_0, value_0)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_9, dummy_9), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_66, dummy_66), (dummy_2, dummy_2), (dummy_3, dummy_3), (dummy_4, dummy_4), (dummy_5, dummy_5), (dummy_6, dummy_6), (key_0, value_0), (dummy_8, dummy_8), (dummy_7, dummy_7)}
T2 = {(dummy_00, dummy_00), (dummy_11, dummy_11), (dummy_22, dummy_22), (dummy_33, dummy_33), (dummy_44, dummy_44), (dummy_55, dummy_55), (dummy_1, dummy_1), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_99, dummy_99)}

-----------------------------------------
Insert data (key_1, value_1)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_00, dummy_00), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_66, dummy_66), (dummy_11, dummy_11), (dummy_3, dummy_3), (dummy_4, dummy_4), (dummy_5, dummy_5), (key_1, value_1), (key_0, value_0), (dummy_8, dummy_8), (dummy_7, dummy_7)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_22, dummy_22), (dummy_33, dummy_33), (dummy_44, dummy_44), (dummy_55, dummy_55), (dummy_1, dummy_1), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_99, dummy_99)}

-----------------------------------------
Insert data (key_2, value_2)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_44, dummy_44), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_66, dummy_66), (dummy_11, dummy_11), (dummy_3, dummy_3), (dummy_55, dummy_55), (dummy_5, dummy_5), (key_2, value_2), (key_0, value_0), (dummy_8, dummy_8), (dummy_7, dummy_7)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_22, dummy_22), (dummy_33, dummy_33), (key_1, value_1), (dummy_4, dummy_4), (dummy_1, dummy_1), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_99, dummy_99)}

-----------------------------------------
Insert data (key_3, value_3)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_99, dummy_99), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_4, dummy_4), (dummy_11, dummy_11), (dummy_3, dummy_3), (dummy_55, dummy_55), (key_3, value_3), (key_2, value_2), (key_0, value_0), (dummy_8, dummy_8), (dummy_7, dummy_7)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_22, dummy_22), (dummy_33, dummy_33), (key_1, value_1), (dummy_66, dummy_66), (dummy_1, dummy_1), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_5, dummy_5)}

-----------------------------------------
Insert data (key_4, value_4)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_66, dummy_66), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_4, dummy_4), (dummy_11, dummy_11), (dummy_3, dummy_3), (dummy_55, dummy_55), (key_3, value_3), (key_2, value_2), (key_0, value_0), (dummy_8, dummy_8), (dummy_7, dummy_7)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_22, dummy_22), (dummy_33, dummy_33), (key_1, value_1), (key_4, value_4), (dummy_1, dummy_1), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_5, dummy_5)}

-----------------------------------------
Insert data (key_5, value_5)

Execute ECALL.

-----check stash candidate-----
stash = {(key_2, value_2), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_4, dummy_4), (key_5, value_5), (dummy_3, dummy_3), (dummy_33, dummy_33), (key_3, value_3), (key_1, value_1), (key_0, value_0), (dummy_8, dummy_8), (dummy_7, dummy_7)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_22, dummy_22), (dummy_11, dummy_11), (dummy_55, dummy_55), (key_4, value_4), (dummy_1, dummy_1), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_5, dummy_5)}

-----------------------------------------
Insert data (key_6, value_6)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_8, dummy_8), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_4, dummy_4), (key_5, value_5), (dummy_3, dummy_3), (key_6, value_6), (key_3, value_3), (key_1, value_1), (key_0, value_0), (dummy_1, dummy_1), (dummy_22, dummy_22)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_33, dummy_33), (dummy_11, dummy_11), (dummy_55, dummy_55), (key_4, value_4), (dummy_7, dummy_7), (dummy_77, dummy_77), (dummy_88, dummy_88), (dummy_5, dummy_5)}

-----------------------------------------
Insert data (key_7, value_7)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_22, dummy_22), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_4, dummy_4), (dummy_88, dummy_88), (dummy_3, dummy_3), (key_6, value_6), (key_3, value_3), (key_1, value_1), (key_7, value_7), (dummy_1, dummy_1), (dummy_7, dummy_7)}
T2 = {(dummy_6, dummy_6), (dummy_2, dummy_2), (dummy_33, dummy_33), (dummy_11, dummy_11), (dummy_55, dummy_55), (key_4, value_4), (key_5, value_5), (dummy_77, dummy_77), (key_0, value_0), (dummy_5, dummy_5)}

-----------------------------------------
Insert data (key_8, value_8)

Execute ECALL.

-----check stash candidate-----
stash = {(key_7, value_7), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (dummy_4, dummy_4), (dummy_88, dummy_88), (dummy_3, dummy_3), (dummy_33, dummy_33), (key_8, value_8), (key_1, value_1), (dummy_6, dummy_6), (dummy_1, dummy_1), (dummy_7, dummy_7)}
T2 = {(key_6, value_6), (dummy_2, dummy_2), (key_3, value_3), (dummy_11, dummy_11), (dummy_55, dummy_55), (key_4, value_4), (key_5, value_5), (dummy_77, dummy_77), (key_0, value_0), (dummy_5, dummy_5)}

-----------------------------------------
Insert data (key_9, value_9)

Execute ECALL.

-----check stash candidate-----
stash = {(dummy_33, dummy_33), (dummy, dummy)}
=============================================================================
SGX_SUCCESS
Exited SGX function successfully.
=============================================================================

Returned integer from ECALL is: 1

T1 = {(dummy_0, dummy_0), (key_4, value_4), (dummy_88, dummy_88), (dummy_3, dummy_3), (key_6, value_6), (key_8, value_8), (key_1, value_1), (dummy_6, dummy_6), (dummy_1, dummy_1), (dummy_7, dummy_7)}
T2 = {(key_9, value_9), (dummy_2, dummy_2), (key_3, value_3), (dummy_11, dummy_11), (dummy_55, dummy_55), (dummy_4, dummy_4), (key_5, value_5), (dummy_77, dummy_77), (key_0, value_0), (dummy_5, dummy_5)}

Whole operations have been executed correctly.
```
### 実装メモ
- 多次元配列のポインタを引数で渡してしまうと先頭のアドレスしかエンクレーブにコピーされないので，きちんと配列を渡す（サイズを指定する必要がある）
- c++オブジェクトを引数として渡すことができない（p90 https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf)
- edlファイルに構造体の定義を書けばエンクレーブ，エンクレーブ外の両方のコードで使える（たぶんMakefileでリンクされているファイルのみ）
- エンクレーブ内でsha256を生成するには<sgx_tcrypto.h>をインクルードする（エンクレーブ内で使える専用のライブラリが用意されている）
- エンクレーブ内ではstring型などは使えない（基本cのみ）
## 疑問点
- stashに入れるデータをクライアントに返す時，ダミーデータも混ぜたほうがいいのか
