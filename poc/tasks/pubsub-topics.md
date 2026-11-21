# 課題 pubsub-topics: Pub/Sub の CreateTopic、GetTopic、ListTopics、DeleteTopic

## 目的

`google.pubsub.v1.Publisher` の `CreateTopic`、`GetTopic`、`ListTopics`、`DeleteTopic` を実装する。状態は、エミュレータのプロセスのメモリに持つ。

## 書いてよいファイル

`services/pubsub/` の直下にある、名前が `.gen.go` で終わらない `.go` ファイルだけを書く。ファイルを足してもよい。そのほかのファイルは、変えない。

実装した RPC のファイルからは、先頭のコメントにある `// SCAFFOLDED, NOT IMPLEMENTED` の行を消す。

## 仕様

この仕様は、PoC の課題として決めたものである。実際の Google Cloud の動作と照合してはいない。エラーは、gRPC のステータスコードで返す。

ファイルの先頭にある契約のコメント（proto から転記したもの）と、この仕様が違うときは、この仕様に従う。

この課題で扱う `Topic` のフィールドは、`name`、`labels`、`state` だけである。ほかのフィールドは、検査の対象にしない。

### CreateTopic

要求は `Topic` である。

1. `name` は `projects/{project}/topics/{topic}` の形でなければならない。`{project}` は 1 文字以上で、`/` を含まない。`{topic}` は 3 文字以上 255 文字以下で、英字で始まる。使える文字は、英数字と `-`、`_`、`.`、`~`、`+`、`%` である。`goog` で始まってはならない。合わないときは `INVALID_ARGUMENT` を返す。
2. 同じ名前のトピックがすでにあるときは `ALREADY_EXISTS` を返す。
3. 成功したら、トピックを保存して返す。`name` と `labels` は、要求の値と同じにする。`state` は、要求の値を使わず、`ACTIVE` にする。
4. 検証は、1、2 の順に行う。

### GetTopic

1. `topic` は `projects/{project}/topics/{topic}` の形でなければならない。`{project}` と `{topic}` は 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. その名前のトピックが無いときは `NOT_FOUND` を返す。
3. あるときは、`CreateTopic` が返したものと同じ内容のトピックを返す。

### ListTopics

1. `project` は `projects/{project}` の形でなければならない。`{project}` は 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. `page_size` が負のときは `INVALID_ARGUMENT` を返す。0 のときは 100 として扱う。1000 より大きいときは 1000 として扱う。
3. 返すのは、その `project` の下にあるトピックだけである。`name` の昇順（バイト列としての比較）に並べる。
4. 1 回の応答には、`page_size` 件までを入れる。続きがあるときは、`next_page_token` に空でない文字列を入れる。続きが無いときは、空にする。
5. `page_token` が空のときは、先頭から返す。前の応答の `next_page_token` が渡されたときは、その続きから返す。そのどちらでもない文字列のときは `INVALID_ARGUMENT` を返す。

### DeleteTopic

1. `topic` の形は、`GetTopic` と同じである。合わないときは `INVALID_ARGUMENT` を返す。
2. その名前のトピックが無いときは `NOT_FOUND` を返す。
3. あるときは、消して、空の応答を返す。
4. 消したトピックは、`GetTopic` で `NOT_FOUND` になり、`ListTopics` に出ない。同じ名前で、もう一度 `CreateTopic` できる。

### 共通

- 別のプロジェクトにある同じ名前のトピックは、別のものとして扱う。
- 複数の要求が同時に来ても、データ競合を起こさない。
- この課題で実装しない RPC は、変えない。

## 確かめ方

リポジトリのルートで、次が通ることを確かめる。

```bash
go build ./...
go vet ./...
```

生成物（`.gen.go` で終わるファイル、`docs/coverage/` の下、`snapshot.json`、`unimplemented.json`）は書かない。`make gen` も `make gen-only` も実行しなくてよい。再生成は、あとの段が行う。
