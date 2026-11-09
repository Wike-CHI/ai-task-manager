# 参与贡献

欢迎 issue 和 PR。这个项目刻意保持"小"：单个 cpp、零第三方依赖、一个 exe。
提 PR 前请先读下面几条，大部分 PR 被打回都是因为踩了这些。

## 环境

| 需要 | 版本 |
|---|---|
| Visual Studio | 2022（含"使用 C++ 的桌面开发"工作负载） |
| Windows SDK | 10.0.19041 或更高（`DwmSetWindowAttribute` 需要） |
| 系统 | Windows 10 1809+ 编译；Win11 才有圆角和自定义标题栏色 |

不需要 CMake、不需要 vcpkg、不需要任何 NuGet 包。

## 编译

```bat
build.bat
```

它会调 `vcvars64.bat`，然后用 `rc.exe` 编译图标资源、`cl.exe` 编译并链接，
产物是当前目录的 `AITaskManager.exe`（约 400 KB）。

手动编译等价命令：

```bat
rc /nologo /fo build\app.res app.rc
cl /nologo /std:c++17 /EHsc /O2 /utf-8 /W3 /Fo:build\ ^
   src\main.cpp build\app.res /Fe:AITaskManager.exe ^
   user32.lib gdi32.lib comctl32.lib psapi.lib shell32.lib dwmapi.lib msimg32.lib advapi32.lib
```

## 代码约定

- **只允许 C++17 标准库 + Win32 API**。引入第三方库（哪怕 header-only）基本不会被接受，
  这个项目的卖点之一是"拷一个 exe 就能跑"。
- 单文件结构：`src/main.cpp`。新增功能优先放在已有段落里，别拆成一堆 .h/.cpp。
- 注释写"为什么"，不写"是什么"。例如：

  ```cpp
  // 用 ListView_SetItemText 宏会漏初始化 LV_ITEM.mask，实测导致列内容变成指针值
  ```

- 字符串一律 `std::wstring` / `L"..."`，界面不出现 ANSI 路径。

## 几个容易踩的坑

| 现象 | 原因 |
|---|---|
| 编译报 `HICON 后跟 = 非法` | 局部变量叫 `small`，`rpcndr.h` 里 `#define small char` |
| 列表列内容变成 `3689343...` | 用了 `ListView_SetItemText` 宏，`LV_ITEM.mask` 未初始化 |
| 窗口跑到屏幕外 | 用了 `tk`/`PlaceWindow` 类似的居中逻辑但没按主屏算 |
| 刷新时整窗闪白 | 少了 `WS_CLIPCHILDREN` 或 `WM_ERASEBKGND` 返回 1 |
| 玻璃主题截图全白 | 开了系统 Acrylic，客户区自绘时它只会让表面带 alpha |

## 提交前自检

- [ ] `build.bat` 通过，无新增 warning（`/W3`）
- [ ] 三种主题都启动过：`AITaskManager.exe` / `glass` / `auto`
- [ ] 切换主题时列表、曲线、标题栏、图标四处都跟着变
- [ ] 连续运行 2 分钟，顶部曲线不闪、列表滚动位置不跳
- [ ] 改动涉及采集逻辑时，对照任务管理器核对一次内存/CPU 数字

## 提交信息

用 Conventional Commits 前缀，中文描述即可：

```
feat: 增加按 CPU 排序
fix: 玻璃主题下曲线标签被卡片裁掉
docs: 补充 CI 发布流程
refactor: 把主题表抽成 Theme 结构
```

PR 描述里写清三件事：**改了什么、为什么改、怎么验证的**（附截图更好）。
CI 会跑编译，红了先看 Actions 日志再 @ 人。

## 关于 Issue

- 报 bug 请附 **Windows 版本（`winver`）**、用的主题、下载的还是自己编译的
- 涉及资源占用异常，附一张「为什么卡」的截图比文字描述有用
- 想加功能，先说场景（你在什么情况下觉得缺这个），比直接给实现方案更容易讨论
