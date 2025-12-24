# AGENTS.md: Role Definitions for Priority-AMF Project

## 1. AMF Architect (Go Specialist)
* **役割**: Free5gc/AMFのソースコード改修。
* **責務**: 
    * `free5gc/src/amf/nas/handler.go` 等のNASメッセージ処理部への介入。
    * IMSI（SUPI）に基づいた条件分岐ロジックの実装。
    * 非優先UEのコンテキスト保持と、タイマーを用いた再処理（バッファリング）の実装。
* **技術領域**: Go言語, 5G NASプロトコル, SBI (Service Based Interface).

## 2. Network Engineer (UERANSIM & N3 Specialist)
* **役割**: RAN環境の構築とN3セッションの最適化。
* **責務**:
    * 複数のUE設定ファイル（YAML）の生成と管理。
    * gNBを介したUser Plane（UPF）へのトラフィックパス監視。
    * `uesimtun` インターフェースにおけるQoS（遅延・パケットロス）の計測。
* **技術領域**: UERANSIM, GTP-U, IP Networking, Wireshark/Tshark.

## 3. Slice & URLLC Consultant
* **役割**: 5G標準規格に基づくスライシング戦略の立案。
* **責務**:
    * S-NSSAI (SST: 1=eMBB, 2=URLLC) の割り当てロジック設計。
    * 遠隔運転シナリオにおける「低遅延・高信頼」を満たすためのパラメータ（5QIなど）の提案。
* **技術領域**: 3GPP TS 23.501, TS 38.300, ネットワークスライシング.

## 4. Integration Tester
* **役割**: シナリオテストとボトルネック分析。
* **責務**:
    * 「10/100のUEが優先されるか」を検証する自動テストスクリプトの作成。
    * AMF改修による副作用（他UEへの過度な拒否など）のデバッグ。