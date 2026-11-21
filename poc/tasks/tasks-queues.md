# 課題 tasks-queues: Cloud Tasks の CreateQueue、GetQueue、ListQueues、DeleteQueue

## 目的

`google.cloud.tasks.v2.CloudTasks` の `CreateQueue`、`GetQueue`、`ListQueues`、`DeleteQueue` を実装する。状態は、エミュレータのプロセスのメモリに持つ。

## 書いてよいファイル

`services/cloudtasks/` の直下にある、名前が `.gen.go` で終わらない `.go` ファイルだけを書く。ファイルを足してもよい。そのほかのファイルは、変えない。

実装した RPC のファイルからは、先頭のコメントにある `// SCAFFOLDED, NOT IMPLEMENTED` の行を消す。

## 仕様

この仕様は、PoC の課題として決めたものである。実際の Google Cloud の動作と照合してはいない。エラーは、gRPC のステータスコードで返す。

ファイルの先頭にある契約のコメント（proto から転記したもの）と、この仕様が違うときは、この仕様に従う。

### CreateQueue

1. `parent` は `projects/{project}/locations/{location}` の形でなければならない。`{project}` と `{location}` は 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. `queue` は設定されていなければならない。`queue.name` は `{parent}/queues/{queue_id}` の形でなければならない。`{queue_id}` は 1 文字以上 100 文字以下で、使える文字は英数字と `-` である。合わないときは `INVALID_ARGUMENT` を返す。
3. 同じ名前のキューがすでにあるときは `ALREADY_EXISTS` を返す。
4. 成功したら、キューを保存して返す。`name` は要求の値と同じにする。`state` は `RUNNING` にする。`rate_limits` と `retry_config` は、要求にある値をそのまま返す。要求に無い値は、補わない。
5. 検証は、1 から 3 の順に行う。

### GetQueue

1. `name` は `projects/{project}/locations/{location}/queues/{queue}` の形でなければならない。どの部分も 1 文字以上で、`/` を含まない。合わないときは `INVALID_ARGUMENT` を返す。
2. その名前のキューが無いときは `NOT_FOUND` を返す。
3. あるときは、`CreateQueue` が返したものと同じ内容のキューを返す。

### ListQueues

1. `parent` は `projects/{project}/locations/{location}` の形でなければならない。合わないときは `INVALID_ARGUMENT` を返す。
2. `filter` は、この課題では扱わない。空でないときは `UNIMPLEMENTED` を返す。
3. `page_size` が負のときは `INVALID_ARGUMENT` を返す。0 のときは 100 として扱う。1000 より大きいときは 1000 として扱う。
4. 返すのは、その `parent` の下にあるキューだけである。`name` の昇順（バイト列としての比較）に並べる。
5. 1 回の応答には、`page_size` 件までを入れる。続きがあるときは、`next_page_token` に空でない文字列を入れる。続きが無いときは、空にする。
6. `page_token` が空のときは、先頭から返す。前の応答の `next_page_token` が渡されたときは、その続きから返す。そのどちらでもない文字列のときは `INVALID_ARGUMENT` を返す。

### DeleteQueue

1. `name` の形は、`GetQueue` と同じである。合わないときは `INVALID_ARGUMENT` を返す。
2. その名前のキューが無いときは `NOT_FOUND` を返す。
3. あるときは、消して、空の応答を返す。
4. 消したキューは、`GetQueue` で `NOT_FOUND` になり、`ListQueues` に出ない。同じ名前で、もう一度 `CreateQueue` できる。

### 共通

- 別のプロジェクトやロケーションにある同じ `queue_id` のキューは、別のものとして扱う。
- 複数の要求が同時に来ても、データ競合を起こさない。
- この課題で実装しない RPC は、変えない。

## 確かめ方

リポジトリのルートで、次が通ることを確かめる。

```bash
go build ./...
go vet ./...
```

生成物（`.gen.go` で終わるファイル、`docs/coverage/` の下、`snapshot.json`、`unimplemented.json`）は書かない。`make gen` も `make gen-only` も実行しなくてよい。再生成は、あとの段が行う。
