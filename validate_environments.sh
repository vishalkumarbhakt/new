#!/bin/bash
# Script to validate the environment setup
# Usage: ./validate_environments.sh

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
PROJECT_BACKEND="$PROJECT_ROOT/Customer-API"

# Check Python and Django
echo -e "${BLUE}Checking Python and Django installation...${NC}"
python_version=$(python3 --version 2>&1)
if [[ $? -ne 0 ]]; then
    echo -e "${RED}Python not found. Please install Python 3.8 or higher.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ $python_version is installed${NC}"

# Check if the project structure is correct
echo -e "${BLUE}Checking project structure...${NC}"
if [ ! -f "$PROJECT_BACKEND/manage.py" ]; then
    echo -e "${RED}❌ Django project structure is not correct. manage.py not found.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Project structure is correct${NC}"

# Check if environment files exist
echo -e "${BLUE}Checking environment files...${NC}"
if [ ! -f "$PROJECT_ROOT/.env.development" ]; then
    echo -e "${RED}❌ .env.development file not found${NC}"
    exit 1
else
    echo -e "${GREEN}✓ .env.development file found${NC}"
fi

if [ ! -f "$PROJECT_ROOT/.env.production" ]; then
    echo -e "${RED}❌ .env.production file not found${NC}"
    exit 1
else
    echo -e "${GREEN}✓ .env.production file found${NC}"
fi

# Check if switch environment script exists
echo -e "${BLUE}Checking environment switching script...${NC}"
if [ ! -f "$PROJECT_ROOT/switch_env.sh" ]; then
    echo -e "${RED}❌ switch_env.sh file not found${NC}"
    exit 1
else
    echo -e "${GREEN}✓ switch_env.sh file found${NC}"
fi

# Test development environment
echo -e "\n${BLUE}Testing DEVELOPMENT environment setup...${NC}"
bash "$PROJECT_ROOT/switch_env.sh" dev

# Verify the .env file was created
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${RED}❌ Failed to create .env file for development${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Development .env file created${NC}"
fi

# Check for required development settings
echo -e "${BLUE}Checking development environment settings...${NC}"
grep -q 'DEBUG=True' "$PROJECT_ROOT/.env"
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️ DEBUG is not set to True in development environment${NC}"
else
    echo -e "${GREEN}✓ DEBUG is correctly set for development${NC}"
fi

# Test production environment
echo -e "\n${BLUE}Testing PRODUCTION environment setup...${NC}"
bash "$PROJECT_ROOT/switch_env.sh" prod

# Verify the .env file was created
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo -e "${RED}❌ Failed to create .env file for production${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Production .env file created${NC}"
fi

# Check for required production settings
echo -e "${BLUE}Checking production environment settings...${NC}"
grep -q 'DEBUG=False' "$PROJECT_ROOT/.env"
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️ DEBUG is not set to False in production environment${NC}"
else
    echo -e "${GREEN}✓ DEBUG is correctly set for production${NC}"
fi

# Verify config matches in settings.py
echo -e "\n${BLUE}Checking Django settings.py configuration...${NC}"
settings_file="$PROJECT_BACKEND/Customer_API/settings.py"

# Check for dotenv loading
grep -q 'from dotenv import load_dotenv' "$settings_file"
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ dotenv import not found in settings.py${NC}"
else
    echo -e "${GREEN}✓ dotenv is properly imported${NC}"
fi

# Check for environment variable usage
grep -q "DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'" "$settings_file"
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️ DEBUG setting might not be using environment variables correctly${NC}"
else
    echo -e "${GREEN}✓ DEBUG uses environment variables correctly${NC}"
fi

# Check SSL/HTTPS configuration
grep -q "USE_HTTPS = os.environ.get('USE_HTTPS', 'False').lower() == 'true'" "$settings_file"
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠️ SSL/HTTPS settings might not be configured correctly${NC}"
else
    echo -e "${GREEN}✓ SSL/HTTPS configuration is in place${NC}"
fi

# Check for domain configuration in production environment
grep -q "SITE_DOMAIN=yourdomain.com" "$PROJECT_ROOT/.env.production"
if [ $? -eq 0 ]; then
    echo -e "${YELLOW}⚠️ Production domain is set to placeholder 'yourdomain.com'. Update with actual domain before deployment.${NC}"
fi

# Switch back to development for convenience
echo -e "\n${GREEN}Switching back to development environment...${NC}"
bash "$PROJECT_ROOT/switch_env.sh" dev

echo -e "\n${GREEN}Environment validation complete!${NC}"
echo -e "${BLUE}Your Django project is configured to handle both development and production environments.${NC}"
echo -e "${BLUE}Use ./switch_env.sh dev|prod to switch between environments.${NC}"
echo -e "\n${GREEN}Switching back to development environment...${NC}"
bash "$PROJECT_ROOT/switch_env.sh" dev

echo -e "\n${GREEN}Environment validation complete!${NC}"
echo -e "${BLUE}Your Django project is configured to handle both development and production environments.${NC}"
echo -e "${BLUE}Use ./switch_env.sh dev|prod to switch between environments.${NC}"
