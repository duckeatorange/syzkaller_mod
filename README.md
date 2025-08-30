# syzkaller_mod

原版为25年4月3日版syzkaller

## 修改的文件

syzkaller_mod/pkg/corpus/corpus.go
syzkaller_mod/pkg/corpus/prio.go
syzkaller_mod/pkg/fuzzer/queue/queue.go
syzkaller_mod/pkg/fuzzer/fuzzer.go
syzkaller_mod/pkg/fuzzer/job.go
syzkaller_mod/pkg/mgrconfig/config.go
syzkaller_mod/pkg/rpctype/rpctype.go

syzkaller_mod/prog/clone.go
syzkaller_mod/prog/generation.go
syzkaller_mod/prog/minimization.go
syzkaller_mod/prog/mutation.go
syzkaller_mod/prog/prog.go

syzkaller_mod/syz-manager/manager.go

syzkaller_mod/vm/adb/adb.go
syzkaller_mod/vm/qemu/qemu.go
syzkaller_mod/vm/vmimpl/merger.go

## 新增的文件

syzkaller_mod/pkg/fuzzer/mab_gmt.go
syzkaller_mod/pkg/glc/glc.go
syzkaller_mod/python （该文件夹下全部文件均为新增的）
