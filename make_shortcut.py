"""给 AI 任务管理器建桌面快捷方式。"""
import os
from pathlib import Path

import win32com.client

EXE = r"D:\AI\hy-mt2-test\ai-taskmgr\AITaskManager.exe"
NAME = "AI 任务管理器.lnk"


def desktop_dir() -> Path:
    for cand in (
        Path(os.path.expanduser("~")) / "Desktop",
        Path(r"E:\Users\Administrator\Desktop"),
        Path(r"C:\Users\Administrator\Desktop"),
    ):
        if cand.exists():
            return cand
    raise SystemExit("找不到桌面目录")


def main() -> None:
    lnk = desktop_dir() / NAME
    shell = win32com.client.Dispatch("WScript.Shell")
    sc = shell.CreateShortCut(str(lnk))
    sc.Targetpath = EXE
    sc.WorkingDirectory = str(Path(EXE).parent)
    sc.Description = "AI 任务管理器：看资源、问原因、直接清理"
    sc.save()
    print("快捷方式:", lnk, "| exists:", lnk.exists())


if __name__ == "__main__":
    main()
