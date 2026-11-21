# 課題 sm-create-get: Secret Manager の CreateSecret と GetSecret

## 目的

`google.cloud.secretmanager.v1.SecretManagerService` の `CreateSecret` と `GetSecret` を実装する。状態は、エミュレータのプロセスのメモリに持つ。

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
5. 成功したら、Secret を保存して返す。返す Secret は、次のとおりにする。
   - `name` は `{parent}/secrets/{secret_id}` にする。要求の `secret.name` は使わない。
   - `replication`、`labels`、`annotations` は、要求の値と同じにする。
   - `create_time` は、作成した時刻にする。
6. 検証は、1 から 4 の順に行う。

### GetSecret

1. `name` は `projects/{project}/secrets/{secret}` の形でなければならない。`{project}` と `{secret}` は 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. その名前の Secret が無いときは `NOT_FOUND` を返す。
3. あるときは、`CreateSecret` が返したものと同じ内容の Secret を返す。`create_time` も同じ値にする。

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
