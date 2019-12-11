# DBG Utils for GDB

## 安装

### Python 
```sh
pip install dbg_utils
```

### IDA

复制 `idp.py` 到 `[IDA INSTALL PATH]/plugins/ida.py` 


## 使用

### 服务端

```sh
idpss
```

### IDA

- 配置

```python
config(server_ip, server_port)
```

- 同步 断点、变量

**Ctrl-Alt-D** 
