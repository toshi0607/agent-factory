# 課題 sm-list-delete: Secret Manager の CreateSecret、ListSecrets、DeleteSecret

## 目的

`google.cloud.secretmanager.v1.SecretManagerService` の `CreateSecret`、`ListSecrets`、`DeleteSecret` を実装する。状態は、エミュレータのプロセスのメモリに持つ。

## 書いてよいファイル

`services/secretmanager/` の直下にある、名前が `.gen.go` で終わらない `.go` ファイルだけを書く。ファイルを足してもよい。そのほかのファイルは、変えない。

実装した RPC のファイルからは、先頭のコメントにある `// SCAFFOLDED, NOT IMPLEMENTED` の行を消す。

## 仕様

この仕様は、PoC の課題として決めたものである。実際の Google Cloud の動作と照合してはいない。エラーは、gRPC のステータスコードで返す。

ファイルの先頭にある契約のコメント（proto から転記したもの）と、この仕様が違うときは、この仕様に従う。たとえば、契約のコメントには `projects/*/locations/*` で始まる名前があるが、この課題では受け付けない。

### CreateSecret

1. `parent` は `projects/{project}` の形でなければならない。`{project}` は 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. `secret_id` は 1 文字以上 255 文字以下で、使える文字は英数字、`_`、`-` である。合わないときは `INVALID_ARGUMENT` を返す。
3. `secret` と `secret.replication` は、どちらも設定されていなければならない。無いときは `INVALID_ARGUMENT` を返す。
4. 同じ名前の Secret がすでにあるときは `ALREADY_EXISTS` を返す。
5. 成功したら、Secret を保存して返す。`name` は `{parent}/secrets/{secret_id}` にする。要求の `secret.name` は使わない。`replication`、`labels`、`annotations` は、要求の値と同じにする。`create_time` は、作成した時刻にする。
6. 検証は、1 から 4 の順に行う。

### ListSecrets

1. `parent` は `projects/{project}` の形でなければならない。合わないときは `INVALID_ARGUMENT` を返す。
2. `filter` は、この課題では扱わない。空でないときは `UNIMPLEMENTED` を返す。
3. `page_size` が負のときは `INVALID_ARGUMENT` を返す。0 のときは 100 として扱う。1000 より大きいときは 1000 として扱う。
4. 返すのは、その `parent` の下にある Secret だけである。`name` の昇順（バイト列としての比較）に並べる。
5. 1 回の応答には、`page_size` 件までを入れる。続きがあるときは、`next_page_token` に空でない文字列を入れる。続きが無いときは、空にする。
6. `page_token` が空のときは、先頭から返す。前の応答の `next_page_token` が渡されたときは、その続きから返す。そのどちらでもない文字列のときは `INVALID_ARGUMENT` を返す。
7. `total_size` には、その `parent` の下にある Secret の総数を入れる。
8. 返す Secret の内容は、`CreateSecret` が返したものと同じにする。

### DeleteSecret

1. `name` は `projects/{project}/secrets/{secret}` の形でなければならない。`{project}` と `{secret}` は 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. その名前の Secret が無いときは `NOT_FOUND` を返す。
3. あるときは、消して、空の応答を返す。`etag` は無視する。
4. 消した Secret は、`ListSecrets` に出ない。同じ `secret_id` で、もう一度 `CreateSecret` できる。

### 共通

- 別のプロジェクトにある同じ `secret_id` の Secret は、別のものとして扱う。
- 複数の要求が同時に来ても、データ競合を起こさない。
- この課題で実装しない RPC は、変えない。

## 確かめ方

リポジトリのルートで、次が通ることを確かめる。

```bash
go build ./...
go vet ./...
```

生成物（`.gen.go` で終わるファイル、`docs/coverage/` の下、`snapshot.json`、`unimplemented.json`）は書かない。`make gen` も `make gen-only` も実行しなくてよい。再生成は、あとの段が行う。
