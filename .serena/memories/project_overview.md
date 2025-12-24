# Project Overview: Priority-Aware AMF Control System

## 1. プロジェクト目的
本プロジェクトは、Free5gcのAMF（Access and Mobility Management Function）を拡張し、UEの識別子（IMSI/SUPI）やスライス情報（S-NSSAI）に基づいた**動的なセッション制御およびトラフィック優先制御**を実現することを目的とする。特に、遠隔運転などのURLLC（超高信頼・低遅延）ユースケースを想定し、特定UEへのリソース優先割り当てをシミュレーション環境で実証する。

## 2. コア機能
* **UE優先度判別**: AMF内のRegistration手順において、IMSIの下一桁や特定のプロファイル（10/100ルールなど）に基づき優先度を定義。
* **PDUセッション制御**: 優先UEに対して優先的にN3トンネルを確立し、非優先UEのセッション要求をAMF/gNBレベルでバッファリングまたはスロットリングする。
* **RRCメッセージ制御**: UERANSIMとAMF間のシグナリングを操作し、高優先度UEの接続遅延を最小化する。
* **URLLCスライシング**: S-NSSAIを用いたネットワークスライシングの概念を導入し、論理的なリソース分離を試行する。

## 3. 技術スタック
* **Core Network**: Free5gc (Go言語)
* **RAN/UE Simulator**: UERANSIM (複数台構成)
* **Language**: Go (Free5gc AMFの改修)
* **Interface**: N1/N2 (NAS/NGAP), N3 (GTP-U)
* **OS**: Linux (Ubuntu 20.04/22.04)

## 4. 開発フェーズ
1.  **Phase 1**: UERANSIM複数台を用いたマルチUE環境の構築。
2.  **Phase 2**: AMFのRegistrationハンドラを拡張し、IMSIによるUE選別ロジックの実装。
3.  **Phase 3**: 優先UE以外のメッセージを一時的に保留（バッファ）するキューイングアルゴリズムの実装。
4.  **Phase 4**: `uesimtun0`等のインターフェースにおけるスループット・遅延の差異の検証。