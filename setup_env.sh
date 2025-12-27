#!/bin/bash

# ========================================================================
# CUSTOMER-API ENVIRONMENT SETUP SCRIPT
# ========================================================================
# This script helps set up environment variables for different environments
# Usage: ./setup_env.sh [development|production|staging]
# ========================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to generate secure secret key
generate_secret_key() {
    python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
}

# Function to validate environment file
validate_env_file() {
    local env_file=$1
    print_info "Validating environment file: $env_file"
    
    # Check for required variables
    required_vars=(
        "DEBUG"
        "DJANGO_SECRET_KEY"
        "ALLOWED_HOSTS"
        "DB_ENGINE"
    )
    
    missing_vars=()
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "$env_file"; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        print_error "Missing required variables in $env_file:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        return 1
    fi
    
    # Check for default/insecure values in production
    if [[ "$env_file" == *"production"* ]]; then
        print_info "Checking for insecure values in production environment..."
        
        if grep -q "django-insecure" "$env_file"; then
            print_error "Production environment uses insecure Django secret key!"
            return 1
        fi
        
        if grep -q "DEBUG=True" "$env_file"; then
            print_error "Production environment has DEBUG=True!"
            return 1
        fi
        
        if grep -q "your-" "$env_file"; then
            print_warning "Production environment contains template values (your-*)"
        fi
    fi
    
    print_success "Environment file validation passed!"
    return 0
}

# Function to setup environment
setup_environment() {
    local env_type=$1
    local env_file=".env.$env_type"
    
    print_info "Setting up $env_type environment..."
    
    # Check if environment file exists
    if [ ! -f "$env_file" ]; then
        print_warning "Environment file $env_file not found!"
        
        if [ -f ".env.template" ]; then
            print_info "Creating $env_file from template..."
            cp ".env.template" "$env_file"
            
            # Customize for environment type
            if [ "$env_type" = "development" ]; then
                sed -i 's/DEBUG=False/DEBUG=True/' "$env_file"
                sed -i 's/DB_ENGINE=django.db.backends.postgresql/DB_ENGINE=django.db.backends.sqlite3/' "$env_file"
                sed -i 's/DB_NAME=your-database-name/DB_NAME=db.sqlite3/' "$env_file"
                sed -i 's/SITE_PROTOCOL=https/SITE_PROTOCOL=http/' "$env_file"
                sed -i 's/yourdomain.com/localhost:8000/' "$env_file"
            fi
            
            print_success "Created $env_file from template"
        else
            print_error "No template file found! Please create .env.template first."
            return 1
        fi
    fi
    
    # Generate new secret key if using default
    if grep -q "your-secret-key-here" "$env_file"; then
        print_info "Generating new Django secret key..."
        new_secret=$(generate_secret_key)
        sed -i "s/your-secret-key-here/$new_secret/" "$env_file"
        print_success "Generated new secret key"
    fi
    
    # Validate the environment file
    if ! validate_env_file "$env_file"; then
        print_error "Environment file validation failed!"
        return 1
    fi
    
    # Create symlink to .env for Django to use
    if [ -f ".env" ]; then
        rm ".env"
    fi
    ln -s "$env_file" ".env"
    print_success "Created symlink: .env -> $env_file"
    
    print_success "$env_type environment setup complete!"
}

# Function to check dependencies
check_dependencies() {
    print_info "Checking dependencies..."
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed!"
        return 1
    fi
    
    # Check if Django is available
    if ! python3 -c "import django" &> /dev/null; then
        print_warning "Django is not installed. Run: pip install -r requirements.txt"
    fi
    
    # Check if .env file exists
    if [ ! -f ".env" ]; then
        print_warning "No .env file found. Environment setup required."
    fi
    
    print_success "Dependency check complete!"
}

# Function to run security checks
run_security_checks() {
    print_info "Running security checks..."
    
    if [ -f "manage.py" ]; then
        python3 manage.py check --deploy 2>/dev/null || print_warning "Some deployment checks failed"
        print_success "Django security checks complete!"
    else
        print_error "manage.py not found!"
        return 1
    fi
}

# Function to show environment info
show_env_info() {
    print_info "Current environment configuration:"
    
    if [ -f ".env" ]; then
        env_target=$(readlink .env)
        echo "  Active environment: $env_target"
        
        debug_value=$(grep "^DEBUG=" .env | cut -d'=' -f2)
        echo "  DEBUG mode: $debug_value"
        
        db_engine=$(grep "^DB_ENGINE=" .env | cut -d'=' -f2)
        echo "  Database: $db_engine"
        
        site_url=$(grep "^SITE_URL=" .env | cut -d'=' -f2)
        echo "  Site URL: $site_url"
    else
        print_warning "No active environment file found"
    fi
}

# Main script logic
main() {
    echo "========================================================================="
    echo "             CUSTOMER-API ENVIRONMENT SETUP SCRIPT"
    echo "========================================================================="
    
    case "${1:-help}" in
        development|dev)
            setup_environment "development"
            ;;
        production|prod)
            setup_environment "production"
            ;;
        staging)
            setup_environment "staging"
            ;;
        check)
            check_dependencies
            run_security_checks
            ;;
        info)
            show_env_info
            ;;
        validate)
            if [ -n "$2" ]; then
                validate_env_file "$2"
            else
                print_error "Please specify environment file to validate"
                exit 1
            fi
            ;;
        help|*)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  development  Set up development environment"
            echo "  production   Set up production environment"
            echo "  staging      Set up staging environment"
            echo "  check        Check dependencies and run security checks"
            echo "  info         Show current environment information"
            echo "  validate     Validate specific environment file"
            echo "  help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 development"
            echo "  $0 production"
            echo "  $0 check"
            echo "  $0 validate .env.production"
            ;;
    esac
}

# Run main function with all arguments
main "$@"
