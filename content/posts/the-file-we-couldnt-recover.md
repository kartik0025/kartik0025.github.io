---
title: "The file we couldn't recover: an ext3 deleted-file investigation"
date: 2026-05-30T00:05:00+05:30
draft: false
tags: ["dfir", "linux", "forensics", "filesystem"]
summary: "A user created five files and deleted some. Recovering them from an ext3 image meant Trash artifacts, orphan inodes full of GNOME metadata — and proving why one file was gone for good."
ShowToc: true
TocOpen: false
cover:
  image: "covers/ext3-deleted-file.png"
  alt: "The file we couldn't recover — an ext3 deleted-file investigation"
  hiddenInSingle: true
---

During a five-day filesystem-forensics bootcamp at NFSU, I was given a forensic image of a Linux pen drive and a one-line task: *do forensics on it.* No scenario, no hints, no list of what to look for — just the image. Everything below, I had to work out on my own.

What I pieced together: a user had created five text files, `1.txt` through `5.txt`, and deleted some of them. Four came back. One — `5.txt` — was gone, and the interesting part was *proving why*. Along the way the filesystem handed me something nobody had asked for: a near minute-by-minute record of what the user had actually been doing. Here's the whole thing, dead ends included.

## First, the wrong way (and why I'm showing it)

Most forensics writeups show only the clean path. The detours taught me more, so they stay in.

My first instinct was to carve — scan the raw bytes for file signatures and pull out anything shaped like a JPEG:

```bash
grep -boa $'\xff\xd8\xff' Sample_03.E01
```

That failed instantly, for an instructive reason: the image was an **E01 (EnCase) container**, which is *compressed*. Byte offsets into it point at compressed data, not real disk sectors. So I exported a raw `.dd` and tried again — and promptly "recovered" a wallpaper that had never been deleted. Blind carving across a whole disk happily hands you files that are still alive. A dedicated free-space carver did better (208 JPEG candidates, exactly one valid) but missed the artifacts that mattered, because they weren't in free space at all.

The pivot was to stop guessing and ask the filesystem **what should be here** before hunting for what's missing:

```bash
fls -r -o 2048 -m / pendrive.dd
```

That one command — a recursive listing that *includes* deleted entries — reframed the entire case.

## Reconnaissance: the filesystem tells on itself

`mmls` put the Linux partition at sector offset **2048** (the standard 1 MiB alignment). `fsstat` identified it:

```text
File System Type: Ext3
Block Size: 4096
Block Groups: 112
...
Orphan inodes: 319100, 319081
```

That last line is the kind of gift you don't ignore. **Orphan inodes** are allocated inodes with zero directory links — typically a file deleted while still open, or an unclean unmount. The superblock was pointing straight at two of them before I'd recovered anything. Hold that thought.

A look under `/home/dora/` showed the usual GNOME layout: `Desktop`, `Documents`, `.cache`, and `.local/share/Trash`. (It was only later that the username clicked — `dora` — and I realized the disk had been built for the exercise, not seized from anyone real.)

## The easy wins: Trash

On a Linux desktop, "deleting" a file in the file manager doesn't `rm` it — it moves it into `~/.local/share/Trash/`, which keeps two things: the content under `files/`, and a small `.trashinfo` record under `info/`:

```bash
icat -o 2048 pendrive.dd 319089
```
```text
[Trash Info]
Path=/home/dora/Desktop/4.txt
DeletionDate=2026-02-08T23:55:41
```

There's the original path and the exact deletion time, handed to me for free. The Trash held `2.txt` and `4.txt`, both recovered intact. Active files `1.txt` and `3.txt` had never been deleted at all.

That left `5.txt` — and it was nowhere in the Trash. Which already said something: it hadn't been deleted through the GUI. It had been `rm`'d, bypassing Trash entirely.

## The orphan inodes: a behavioral goldmine

Back to the two orphans `fsstat` flagged. I pulled inode 319100 (32 KiB, link count 0) and ran it through `xxd`:

```bash
istat -o 2048 pendrive.dd 319100
xxd orphan_319100.bin | head
```
```text
... 6a 6f 75 72   →  "jour" (journal)
/Desktop/3.txt
/Desktop/4.txt
gedit-position
```

This wasn't user data — it was a **GEdit session journal**, a GVFS metadata file. It recorded which files had been *open in the text editor* (`3.txt` and `4.txt`) and even the cursor position (offset 14, near the end of a 15-byte file). The second orphan, inode 319081, was **Nautilus metadata** — desktop icon positions and file-manager state:

```bash
strings orphan_319081.bin | grep -E "txt|Trash"
```
```text
Folder
4.txt
3.txt
Trash
2.txt
1.txt
```

This is the part I think is genuinely underrated. A filesystem timestamp tells you a file was touched; this desktop-environment metadata tells you what the *person* did — which files they opened versus merely created, how the desktop was arranged, what sat in the Trash. And one thing stood out by its **absence**: `5.txt` appears nowhere in it. It was never opened in the editor. Created, and deleted, without ever being read.

## Why 5.txt was gone for good

The headline mystery. `fls -d` (deleted entries only) showed `5.txt` pointing at inode **319070**, flagged `realloc`:

```text
r/r * 319070(realloc):  5.txt
```

But pulling that inode's content gave the wrong answer:

```bash
icat -o 2048 pendrive.dd 319070
```
```text
"This is file 1"
```

That's not `5.txt`'s content — that's `4.txt`'s. The `realloc` flag is the tell: after `5.txt` was deleted and its inode freed, inode **319070 was reused** by `4.txt`. The metadata slot now describes a completely different file. And the data blocks? One last check:

```bash
grep -abo "This is file 5" pendrive.dd
# (no matches)
```

Nothing. The content had been overwritten too. `5.txt` wasn't hidden or corrupted — it was genuinely, permanently destroyed.

## Putting time back together

Stitching inode MAC times together with the GVFS metadata timestamps reconstructed a roughly eight-minute session:

| Time (IST) | Event |
|---|---|
| 23:52:06 | `3.txt` created |
| 23:53:41 | `4.txt` opened in gedit |
| 23:55:40 | `5.txt` created (inode 319070) |
| 23:55:41 | `2.txt` moved to Trash |
| 23:56:33 | `5.txt` deleted (inode freed) |
| 00:00:35 | inode 319070 reused by `4.txt` |

`5.txt` existed for **53 seconds**, and its inode was recycled about four minutes later. Recovery was a race it had already lost.

## What I took away

- **Deletion is not destruction — until the inode is reused or the blocks are overwritten.** Recovery is a race against system activity, and sometimes you lose it — which is itself a defensible, documentable finding.
- **Ask the filesystem what *should* exist before you carve.** Filesystem-aware analysis beat blind carving at every step; blind carving actively misled me with files that were never deleted.
- **Orphan inodes and desktop-environment metadata are evidence.** The GEdit journal and Nautilus state reconstructed user *behavior*, not just file contents — and `5.txt`'s absence from them was as informative as the files I recovered.
- **Keep your dead ends.** The failed carving attempts are exactly what taught me which kind of evidence I was actually looking for.

The tooling is all [The Sleuth Kit](https://www.sleuthkit.org/) — `mmls`, `fsstat`, `fls`, `istat`, `icat` — plus `xxd` and `grep`. None of it is exotic. The investigation lived in the order you ask the questions.
