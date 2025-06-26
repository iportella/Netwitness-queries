# 📡 Queries para NetWitness

Repositório com consultas otimizadas para uso na ferramenta **NetWitness**, com foco em **monitoramento de tráfego malicioso, conexões externas suspeitas e atividades de navegação não autorizadas**.

## 📌 Objetivos
- Detectar conexões de/para endereços IP públicos.
- Identificar tentativas de acesso externo a serviços como SSH, RDP, FTP, HTTP, SMB, SMTP, etc.
- Mapear acessos a sites impróprios (pornografia, apostas).
- Monitorar uso de redes sociais em ambientes restritos.

## 📁 Estrutura das Queries
As queries estão divididas por categorias, como:

### 🔍 Conexões Externas (Origem ou Destino)
```sql
(ip.src!=[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16] || ip.dst!=[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16])
```

### 🔐 Conexões Externas para Protocolos Específicos
Exemplo - SSH:
```sql
(ip.src != 10.0.0.0/8 && ip.src != 172.16.0.0/12 && ip.src != 192.168.0.0/16) && ip.dstport = 22 && action != "blocked"
```
Outros protocolos suportados: Telnet (23), RDP (3389), HTTP (80), SMB (445), SMTP (25), FTP (21).

### 🌍 Conexões de Saída para IPs Públicos
Exemplo - HTTP:
```sql
(ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16) && ip.dstport = 80 && action != "blocked"
```

### 🔞 Sites Inapropriados - Pornografia
```sql
action != "blocked" && host.dst contains "xvideos"
action != "blocked" && host.dst contains "porn"
action != "blocked" && host.dst contains "onlyfans"
```

### 🎰 Sites de Apostas
```sql
action != "blocked" && host.dst contains "bet"
action != "blocked" && host.dst contains "aposta"
action != "blocked" && host.dst contains "blaze"
```

### 📱 Redes Sociais
```sql
action != "blocked" && host.dst contains "facebook"
action != "blocked" && host.dst contains "instagram"
action != "blocked" && host.dst contains "twitter"
```

---

# 📡 NetWitness Queries

Repository containing optimized queries for **NetWitness**, focused on detecting **malicious or suspicious traffic**, **external access attempts**, and **unauthorized browsing**.

## 📌 Purpose
- Detect connections from/to public IP ranges.
- Identify external access attempts to services like SSH, RDP, FTP, HTTP, SMB, SMTP, etc.
- Monitor access to inappropriate websites (porn, gambling).
- Track social media access in restricted environments.

## 📁 Query Structure

### 🔍 External Connections (Inbound or Outbound)
```sql
(ip.src!=[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16] || ip.dst!=[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16])
```

### 🔐 External Attempts to Specific Protocols
Example - SSH:
```sql
(ip.src != 10.0.0.0/8 && ip.src != 172.16.0.0/12 && ip.src != 192.168.0.0/16) && ip.dstport = 22 && action != "blocked"
```

### 🌍 Outbound to Public Destinations
Example - HTTP:
```sql
(ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16) && ip.dstport = 80 && action != "blocked"
```

### 🔞 Inappropriate Websites - Porn
```sql
action != "blocked" && host.dst contains "xvideos"
action != "blocked" && host.dst contains "porn"
action != "blocked" && host.dst contains "onlyfans"
```

### 🎰 Gambling Websites
```sql
action != "blocked" && host.dst contains "bet"
action != "blocked" && host.dst contains "aposta"
action != "blocked" && host.dst contains "blaze"
```

### 📱 Social Media Platforms
```sql
action != "blocked" && host.dst contains "facebook"
action != "blocked" && host.dst contains "instagram"
action != "blocked" && host.dst contains "twitter"
```

---

> ⚠️ Este repositório tem propósito educacional e para uso em ambientes devidamente autorizados.
> 
> ⚠️ This repository is intended for educational use in properly authorized environments only.
