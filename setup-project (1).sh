#!/bin/bash
# ClusterNodes Quick Setup Script
# Run this script to set up the complete project structure

set -e

echo "🚀 ClusterNodes - Quick Setup Script"
echo "======================================"
echo ""

# Create main project directory
PROJECT_NAME="ClusterNodes"
echo "📁 Creating project directory: $PROJECT_NAME"
mkdir -p $PROJECT_NAME
cd $PROJECT_NAME

# Create backend structure
echo "📁 Creating backend structure..."
mkdir -p backend/{core,analysis,ai,reports,storage,cli}
touch backend/__init__.py
touch backend/{core,analysis,ai,reports,storage,cli}/__init__.py

# Create frontend structure
echo "📁 Creating frontend structure..."
mkdir -p frontend/{src/components,public}

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data/{snapshots,reports}

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/
*.egg-info/
.pytest_cache/

# Node
node_modules/
dist/
.cache/
yarn.lock
package-lock.json

# IDE
.vscode/
.idea/
*.swp
*.swo

# Env files
*.env
!.env.example

# Data
data/snapshots/*.json
data/reports/*.pdf

# OS
.DS_Store
Thumbs.db

# Logs
*.log
EOF

# Create backend .env template
echo "📝 Creating backend/.env template..."
cat > backend/.env.example << 'EOF'
EMERGENT_LLM_KEY=your-emergent-key-here
PORT=8001
HOST=0.0.0.0
EOF

# Create frontend .env template
echo "📝 Creating frontend/.env template..."
cat > frontend/.env.example << 'EOF'
REACT_APP_BACKEND_URL=http://localhost:8001
EOF

# Create backend requirements.txt
echo "📝 Creating backend/requirements.txt..."
cat > backend/requirements.txt << 'EOF'
fastapi==0.115.0
uvicorn[standard]==0.32.0
pydantic==2.9.0
networkx==3.3
matplotlib==3.9.0
python-dotenv==1.0.1
fpdf2==2.7.9
typer==0.12.5
requests==2.32.3
pydantic-settings==2.5.2
python-multipart==0.0.9
aiofiles==24.1.0
emergentintegrations
EOF

# Create frontend package.json
echo "📝 Creating frontend/package.json..."
cat > frontend/package.json << 'EOF'
{
  "name": "clusternodes-frontend",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "axios": "^1.7.2",
    "cytoscape": "^3.30.2"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.3",
    "vite": "^5.4.8",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.47",
    "tailwindcss": "^3.4.15"
  }
}
EOF

# Create vite.config.js
echo "📝 Creating frontend/vite.config.js..."
cat > frontend/vite.config.js << 'EOF'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
});
EOF

# Create tailwind.config.js
echo "📝 Creating frontend/tailwind.config.js..."
cat > frontend/tailwind.config.js << 'EOF'
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        navy: '#090e1a',
        'navy-2': '#0c1220',
        'navy-3': '#101828',
        card: '#111927',
        'card-2': '#162033',
      },
    },
  },
  plugins: [],
};
EOF

# Create postcss.config.js
echo "📝 Creating frontend/postcss.config.js..."
cat > frontend/postcss.config.js << 'EOF'
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
EOF

# Create index.html
echo "📝 Creating frontend/index.html..."
cat > frontend/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>ClusterNodes - Kubernetes Security Analysis</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
EOF

# Create README.md
echo "📝 Creating README.md..."
cat > README.md << 'EOF'
# ClusterNodes - Kubernetes Security Analysis Tool

Graph-powered Kubernetes RBAC security analysis with AI-driven attack path detection.

## Quick Start

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your EMERGENT_LLM_KEY
python -m uvicorn server:app --reload
```

### Frontend Setup
```bash
cd frontend
yarn install
cp .env.example .env
yarn dev
```

### Access
- Frontend: http://localhost:3000
- Backend API: http://localhost:8001
- API Docs: http://localhost:8001/docs

## Features
- Graph-based attack path detection
- BFS blast radius analysis
- Dijkstra's shortest attack paths
- DFS circular permission detection
- CVE vulnerability scanning
- AI-powered remediation
- PDF security reports
- Temporal snapshots

## Documentation
See `/docs/` for complete documentation.
EOF

# Create VS Code settings
echo "📝 Creating VS Code workspace settings..."
mkdir -p .vscode
cat > .vscode/settings.json << 'EOF'
{
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "[python]": {
    "editor.tabSize": 4
  },
  "[javascript]": {
    "editor.tabSize": 2
  },
  "[javascriptreact]": {
    "editor.tabSize": 2
  },
  "files.exclude": {
    "**/__pycache__": true,
    "**/node_modules": true,
    "**/.pytest_cache": true
  }
}
EOF

# Create run scripts
echo "📝 Creating run scripts..."

# Backend run script
cat > run-backend.sh << 'EOF'
#!/bin/bash
cd backend
python -m uvicorn server:app --host 0.0.0.0 --port 8001 --reload
EOF
chmod +x run-backend.sh

# Frontend run script
cat > run-frontend.sh << 'EOF'
#!/bin/bash
cd frontend
yarn dev
EOF
chmod +x run-frontend.sh

echo ""
echo "✅ Project structure created successfully!"
echo ""
echo "📋 Next Steps:"
echo "1. Copy all your source code files into the respective directories"
echo "2. Set up environment variables:"
echo "   cp backend/.env.example backend/.env"
echo "   cp frontend/.env.example frontend/.env"
echo "   # Edit .env files with your keys"
echo ""
echo "3. Install dependencies:"
echo "   cd backend && pip install -r requirements.txt"
echo "   cd ../frontend && yarn install"
echo ""
echo "4. Run the application:"
echo "   ./run-backend.sh   # Terminal 1"
echo "   ./run-frontend.sh  # Terminal 2"
echo ""
echo "5. Open http://localhost:3000 in your browser"
echo ""
echo "📚 For complete documentation, see:"
echo "   - README.md"
echo "   - FILE_STRUCTURE.md (copy from original project)"
echo "   - FEATURES.md (copy from original project)"
echo ""
echo "🎉 Happy coding!"
