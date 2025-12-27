#!/bin/bash
# Script to switch between development and production environments
# Usage: ./switch_env.sh [dev|prod]

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ENV_TYPE="$1"

if [[ -z "$ENV_TYPE" ]]; then
  echo -e "${BLUE}Usage: $0 [dev|prod]${NC}"
  echo -e "  ${GREEN}dev${NC}  - Switch to development environment"
  echo -e "  ${YELLOW}prod${NC} - Switch to production environment"
  exit 1
fi

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Check if environment files exist
check_env_files() {
  if [ ! -f "$PROJECT_ROOT/.env.development" ]; then
    echo -e "${RED}Error: .env.development file not found in $PROJECT_ROOT${NC}"
    return 1
  fi
  
  if [ ! -f "$PROJECT_ROOT/.env.production" ]; then
    echo -e "${RED}Error: .env.production file not found in $PROJECT_ROOT${NC}"
    return 1
  fi
  
  return 0
}

# Create a backup of the current .env file
backup_env() {
  if [ -f "$PROJECT_ROOT/.env" ]; then
    local timestamp=$(date +"%Y%m%d%H%M%S")
    cp "$PROJECT_ROOT/.env" "$PROJECT_ROOT/.env.backup.$timestamp"
    echo -e "${BLUE}Current .env file backed up as .env.backup.$timestamp${NC}"
  fi
}

# Switch to the specified environment
switch_environment() {
  case "$1" in
    dev|development)
      echo -e "${GREEN}Switching to DEVELOPMENT environment...${NC}"
      if [ -f "$PROJECT_ROOT/.env" ]; then
        rm "$PROJECT_ROOT/.env"
      fi
      cp "$PROJECT_ROOT/.env.development" "$PROJECT_ROOT/.env"
      echo -e "${GREEN}Environment switched to DEVELOPMENT.${NC}"
      echo -e "${BLUE}Remember to restart your services.${NC}"
      ;;
      
    prod|production)
      echo -e "${YELLOW}Switching to PRODUCTION environment...${NC}"
      if [ -f "$PROJECT_ROOT/.env" ]; then
        rm "$PROJECT_ROOT/.env"
      fi
      cp "$PROJECT_ROOT/.env.production" "$PROJECT_ROOT/.env"
      echo -e "${YELLOW}Environment switched to PRODUCTION.${NC}"
      echo -e "${BLUE}Remember to restart your services.${NC}"
      echo -e "${RED}WARNING: Make sure production credentials are properly set in .env.production before deploying.${NC}"
      ;;
      
    *)
      echo -e "${RED}Invalid environment type: $1${NC}"
      echo -e "Use '${GREEN}dev${NC}' for development or '${YELLOW}prod${NC}' for production"
      return 1
      ;;
  esac
  
  return 0
}

# Validate key settings in .env file
validate_env() {
  local env=$1
  local env_file="$PROJECT_ROOT/.env"
  
  if [ ! -f "$env_file" ]; then
    echo -e "${RED}Error: .env file not found after switching environments${NC}"
    return 1
  fi
  
  echo -e "${BLUE}Validating environment settings...${NC}"
  
  # Source the .env file to get variables
  set -a
  source "$env_file"
  set +a
  
  # Basic validation
  if [ "$env" == "prod" ] || [ "$env" == "production" ]; then
    if [ "$DEBUG" == "True" ]; then
      echo -e "${RED}WARNING: DEBUG is set to True in production environment!${NC}"
    fi
    
    if [ -z "$DJANGO_SECRET_KEY" ] || [ "$DJANGO_SECRET_KEY" == "your-secure-secret-key-here" ]; then
      echo -e "${RED}WARNING: DJANGO_SECRET_KEY is not properly set for production!${NC}"
    fi
    
    # Check PostgreSQL settings
    if [ "$DB_ENGINE" == "django.db.backends.postgresql" ]; then
      if [ -z "$DB_NAME" ] || [ "$DB_NAME" == "your_db_name" ]; then
        echo -e "${RED}WARNING: Database name not properly configured for production${NC}"
      fi
      if [ -z "$DB_USER" ] || [ "$DB_USER" == "your_db_user" ]; then
        echo -e "${RED}WARNING: Database user not properly configured for production${NC}"
      fi
      if [ -z "$DB_PASSWORD" ] || [ "$DB_PASSWORD" == "your_secure_password" ]; then
        echo -e "${RED}WARNING: Database password not properly configured for production${NC}"
      fi
      
      # Optional: Test database connection if we have credentials
      if [ ! -z "$DB_NAME" ] && [ ! -z "$DB_USER" ] && [ ! -z "$DB_PASSWORD" ]; then
        echo -e "${BLUE}Testing database connection...${NC}"
        if command -v psql &> /dev/null; then
          PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c '\q' &> /dev/null
          if [ $? -eq 0 ]; then
            echo -e "${GREEN}Database connection successful${NC}"
          else
            echo -e "${RED}WARNING: Could not connect to database. Check credentials and network.${NC}"
            
            # Ask if the user wants to continue despite connection failure
            read -p "Continue with production environment despite database connection failure? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
              echo -e "${YELLOW}Aborting production environment switch.${NC}"
              # Switch back to development
              cp "$PROJECT_ROOT/.env.development" "$PROJECT_ROOT/.env"
              echo -e "${GREEN}Switched back to development environment.${NC}"
              return 1
            else
              echo -e "${YELLOW}Continuing with production environment despite database issues.${NC}"
            fi
          fi
        else
          echo -e "${YELLOW}Note: psql not available. Skipping database connection test.${NC}"
        fi
      fi
    fi
    
    # Check email settings
    if [ -z "$EMAIL_HOST_USER" ] || [ "$EMAIL_HOST_USER" == "your_email@gmail.com" ]; then
      echo -e "${RED}WARNING: Email settings not properly configured for production${NC}"
    fi
    
    # Check Paytm settings
    if [ -z "$PAYTM_MERCHANT_ID" ] || [ "$PAYTM_MERCHANT_ID" == "your_merchant_id" ]; then
      echo -e "${RED}WARNING: Paytm integration not properly configured for production${NC}"
    fi
  fi
  
  # Show current settings
  echo -e "${BLUE}Current environment settings:${NC}"
  echo -e "  DEBUG: ${YELLOW}$DEBUG${NC}"
  echo -e "  SERVER_PORT: ${YELLOW}$SERVER_PORT${NC}"
  echo -e "  ALLOWED_HOSTS: ${YELLOW}$ALLOWED_HOSTS${NC}"
  echo -e "  DB_ENGINE: ${YELLOW}$DB_ENGINE${NC}"
  echo -e "  SITE_PROTOCOL: ${YELLOW}$SITE_PROTOCOL${NC}"
  echo -e "  SITE_DOMAIN: ${YELLOW}$SITE_DOMAIN${NC}"
  
  return 0
}

# Main execution
if check_env_files; then
  backup_env
  if switch_environment "$ENV_TYPE"; then
    validate_env "$ENV_TYPE"
    echo -e "${GREEN}Done!${NC}"
  fi
else
  echo -e "${RED}Environment switch failed.${NC}"
  exit 1
fi
