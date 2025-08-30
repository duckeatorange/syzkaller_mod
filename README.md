# syzkaller_mod

本项目基于 **syzkaller**（原版 2025 年 4 月 3 日版本）进行修改和扩展。  

---

## 修改内容

### 修改的文件
- `syzkaller_mod/pkg/corpus/`
  - `corpus.go`
  - `prio.go`
- `syzkaller_mod/pkg/fuzzer/`
  - `queue/queue.go`
  - `fuzzer.go`
  - `job.go`
- `syzkaller_mod/pkg/mgrconfig/config.go`
- `syzkaller_mod/pkg/rpctype/rpctype.go`

- `syzkaller_mod/prog/`
  - `clone.go`
  - `generation.go`
  - `minimization.go`
  - `mutation.go`
  - `prog.go`

- `syzkaller_mod/syz-manager/manager.go`

- `syzkaller_mod/vm/`
  - `adb/adb.go`
  - `qemu/qemu.go`
  - `vmimpl/merger.go`

---

### 新增的文件
- `syzkaller_mod/pkg/fuzzer/mab_gmt.go`
- `syzkaller_mod/pkg/glc/glc.go`
- `syzkaller_mod/python/`  
  （该文件夹下的全部文件均为新增）

---
