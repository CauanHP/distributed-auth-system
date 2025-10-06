# Distributed Authentication and Authorization System

Um sistema avançado de autenticação e autorização distribuído com JWT, OAuth2, RBAC, MFA, SSO e auditoria completa, demonstrando expertise em segurança, arquitetura distribuída e gerenciamento de identidades.

## 🚀 Características

- **Autenticação JWT** com refresh tokens
- **OAuth2** para autorização de terceiros
- **RBAC (Role-Based Access Control)** granular
- **MFA (Multi-Factor Authentication)** com TOTP
- **SSO (Single Sign-On)** distribuído
- **Gerenciamento de Sessões** avançado
- **Rate Limiting** inteligente
- **Auditoria Completa** de eventos
- **Dashboard Administrativo** com Streamlit
- **Cache Distribuído** com Redis
- **Banco de Dados** PostgreSQL
- **API RESTful** completa

## 🏗️ Arquitetura

```
app/
├── services/
│   ├── auth_service.py         # Autenticação principal
│   ├── oauth_service.py        # OAuth2 e SSO
│   ├── rbac_service.py         # Controle de acesso baseado em roles
│   ├── mfa_service.py          # Autenticação de dois fatores
│   └── audit_service.py        # Auditoria e logging
├── core/
│   ├── rate_limiter.py         # Rate limiting
│   ├── session_manager.py      # Gerenciamento de sessões
│   └── security.py             # Utilitários de segurança
├── models/                     # Modelos do banco de dados
└── api/                        # Endpoints da API
```

## 🛠️ Tecnologias

- **FastAPI** - API RESTful moderna
- **PostgreSQL** - Banco de dados principal
- **Redis** - Cache e sessões
- **JWT** - Tokens de autenticação
- **OAuth2** - Autorização de terceiros
- **TOTP** - Autenticação de dois fatores
- **SQLAlchemy** - ORM
- **Alembic** - Migrações
- **Streamlit** - Dashboard administrativo
- **Celery** - Tarefas assíncronas
- **Pydantic** - Validação de dados

## 📦 Instalação

1. Clone o repositório:
```bash
git clone <repository-url>
cd distributed-auth-system
```

2. Crie um ambiente virtual:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure as variáveis de ambiente:
```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

5. Execute as migrações:
```bash
alembic upgrade head
```

## 🚀 Uso

### 1. Iniciar o Sistema

```bash
# Iniciar a API
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Em outro terminal, iniciar o dashboard
streamlit run dashboard.py --server.port 8501
```

### 2. Acessar os Serviços

- **API**: http://localhost:8000/docs
- **Dashboard**: http://localhost:8501

## 📊 Funcionalidades

### 1. Autenticação JWT
- **Access Tokens** com expiração configurável
- **Refresh Tokens** para renovação automática
- **Token Blacklisting** para logout seguro
- **Validação** de tokens em tempo real
- **Claims** personalizados

### 2. OAuth2 e SSO
- **Múltiplos Providers** (Google, GitHub, Microsoft)
- **Authorization Code Flow** completo
- **PKCE** para segurança adicional
- **State Parameter** para proteção CSRF
- **Token Exchange** seguro

### 3. RBAC (Role-Based Access Control)
- **Roles** hierárquicos
- **Permissions** granulares
- **Resource-based** permissions
- **Action-based** permissions
- **Temporal** permissions (expiração)
- **Cache** de permissões

### 4. MFA (Multi-Factor Authentication)
- **TOTP** com Google Authenticator
- **QR Code** generation
- **Backup Codes** para recuperação
- **SMS** como alternativa
- **Email** como alternativa
- **Hardware Tokens** (FIDO2)

### 5. Gerenciamento de Sessões
- **Sessões Distribuídas** com Redis
- **Session Timeout** configurável
- **Concurrent Sessions** limit
- **Session Revocation** em massa
- **Session Analytics** em tempo real

### 6. Rate Limiting
- **IP-based** rate limiting
- **User-based** rate limiting
- **Endpoint-specific** limits
- **Sliding Window** algorithm
- **Whitelist/Blacklist** support

### 7. Auditoria e Compliance
- **Event Logging** completo
- **Audit Trail** imutável
- **Compliance** com GDPR/SOX
- **Real-time** monitoring
- **Alerting** para eventos críticos

### 8. Dashboard Administrativo
- **User Management** completo
- **Role Management** visual
- **Permission Management** granular
- **Session Monitoring** em tempo real
- **Audit Logs** com filtros
- **Security Analytics** avançadas

## 🎯 Casos de Uso

### Empresas
- **SSO** para aplicações internas
- **RBAC** para controle de acesso
- **MFA** para segurança adicional
- **Auditoria** para compliance

### SaaS
- **OAuth2** para integração com terceiros
- **Multi-tenant** authentication
- **API** authentication
- **Webhook** security

### Governo
- **High Security** authentication
- **Compliance** com regulamentações
- **Audit Trail** completo
- **Identity Verification**

## 📈 Exemplos de Uso

### 1. Registro de Usuário

```python
import requests

# Registrar novo usuário
user_data = {
    "username": "john_doe",
    "email": "john@example.com",
    "password": "secure_password123",
    "full_name": "John Doe"
}

response = requests.post("http://localhost:8000/api/v1/auth/register", json=user_data)
result = response.json()

print(f"User registered: {result['user']['username']}")
```

### 2. Autenticação com MFA

```python
# Login com MFA
login_data = {
    "email": "john@example.com",
    "password": "secure_password123",
    "mfa_code": "123456"  # Código do Google Authenticator
}

response = requests.post("http://localhost:8000/api/v1/auth/login", json=login_data)
tokens = response.json()

access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]
```

### 3. Verificação de Permissões

```python
# Verificar permissão
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(
    "http://localhost:8000/api/v1/auth/check-permission",
    headers=headers,
    params={"resource": "users", "action": "read"}
)

has_permission = response.json()["has_permission"]
```

### 4. OAuth2 Flow

```python
# Iniciar OAuth2 flow
oauth_url = "http://localhost:8000/api/v1/oauth/authorize"
params = {
    "client_id": "your_client_id",
    "redirect_uri": "http://localhost:3000/callback",
    "response_type": "code",
    "scope": "read write",
    "state": "random_state_string"
}

# Redirecionar usuário para oauth_url
# Após autorização, receber código no callback
```

### 5. Gerenciamento de Roles

```python
# Atribuir role a usuário
role_assignment = {
    "user_id": "user_123",
    "role_id": "role_456",
    "assigned_by": "admin_user"
}

response = requests.post(
    "http://localhost:8000/api/v1/rbac/assign-role",
    json=role_assignment,
    headers={"Authorization": f"Bearer {access_token}"}
)
```

## 🔧 Configuração Avançada

### Variáveis de Ambiente

```env
# Database
DATABASE_URL=postgresql://user:password@localhost/auth_system

# Redis
REDIS_URL=redis://localhost:6379

# Security
SECRET_KEY=your-super-secret-key-here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# OAuth2
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# MFA
MFA_ISSUER_NAME=YourApp
MFA_BACKUP_CODES_COUNT=10

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST=10

# Session
SESSION_TIMEOUT_SECONDS=3600
MAX_CONCURRENT_SESSIONS=5
```

### Configuração de Roles

```python
# Criar roles personalizados
roles = [
    {
        "name": "admin",
        "description": "Administrator with full access",
        "permissions": ["*:*"]
    },
    {
        "name": "user",
        "description": "Regular user with limited access",
        "permissions": ["users:read", "profile:write"]
    },
    {
        "name": "moderator",
        "description": "Content moderator",
        "permissions": ["content:read", "content:write", "users:read"]
    }
]
```

### Configuração de Permissões

```python
# Criar permissões granulares
permissions = [
    {
        "name": "read_users",
        "resource": "users",
        "action": "read",
        "description": "Read user information"
    },
    {
        "name": "write_users",
        "resource": "users",
        "action": "write",
        "description": "Create and update users"
    },
    {
        "name": "delete_users",
        "resource": "users",
        "action": "delete",
        "description": "Delete users"
    }
]
```

## 🧪 Testes

```bash
# Executar testes
pytest tests/

# Com cobertura
pytest --cov=app tests/

# Testes específicos
pytest tests/test_auth_service.py
pytest tests/test_rbac_service.py
pytest tests/test_oauth_service.py
```

## 📊 Métricas e Performance

### Métricas de Segurança
- **Failed Login Attempts** por IP/usuário
- **Account Lockouts** em tempo real
- **Suspicious Activities** detection
- **Security Score** baseado em comportamento

### Performance
- **Token Validation** < 10ms
- **Permission Check** < 5ms
- **Session Lookup** < 2ms
- **Rate Limiting** < 1ms

### Escalabilidade
- **Horizontal Scaling** com Redis
- **Load Balancing** ready
- **Database Sharding** support
- **Microservices** architecture

## 🚀 Deploy

### Docker

```bash
# Build da imagem
docker build -t distributed-auth-system .

# Executar container
docker run -p 8000:8000 -p 8501:8501 distributed-auth-system
```

### Docker Compose

```yaml
version: '3.8'
services:
  auth-api:
    build: .
    ports:
      - "8000:8000"
      - "8501:8501"
    environment:
      - DATABASE_URL=postgresql://user:password@postgres:5432/auth_system
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
  
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: auth_system
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-system
  template:
    metadata:
      labels:
        app: auth-system
    spec:
      containers:
      - name: auth-api
        image: distributed-auth-system:latest
        ports:
        - containerPort: 8000
        - containerPort: 8501
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: redis-url
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

## 📚 Documentação

- **API Docs**: http://localhost:8000/docs
- **OAuth2 Docs**: http://localhost:8000/oauth/docs
- **RBAC Docs**: http://localhost:8000/rbac/docs
- **Streamlit Docs**: https://docs.streamlit.io

## 🔒 Segurança

### Boas Práticas Implementadas
- **Password Hashing** com bcrypt
- **JWT** com assinatura segura
- **Rate Limiting** para prevenir ataques
- **CSRF Protection** em formulários
- **XSS Protection** com headers
- **SQL Injection** prevention
- **Audit Logging** completo

### Compliance
- **GDPR** compliance
- **SOX** compliance
- **HIPAA** ready
- **PCI DSS** ready

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👨‍💻 Autor

[Seu Nome] - [seu.email@exemplo.com]

## 🙏 Agradecimentos

- FastAPI por um framework incrível
- PostgreSQL pela confiabilidade
- Redis pela performance
- JWT por tokens seguros
- OAuth2 pela padronização
- A comunidade de segurança por todas as boas práticas

