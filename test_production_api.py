#!/usr/bin/env python3
"""
Production API Test Script for Multi-Store Cart
Test the multi-store cart functionality on customer-api.s2cart.me/

Usage:
    python3 test_production_api.py

Requirements:
    pip install requests
"""

import requests
import json
import sys

# Configuration
BASE_URL = "https://customer-api.s2cart.me/api/auth"
USERNAME = "testuser"  # Change this to your test username
PASSWORD = "testpass123"  # Change this to your test password

class S2CartAPITester:
    def __init__(self):
        self.base_url = BASE_URL
        self.jwt_token = None
        self.headers = {}
    
    def login(self):
        """Login and get JWT token"""
        print("🔐 Logging in...")
        
        login_data = {
            "username": USERNAME,
            "password": PASSWORD,
            "device_type": "API"
        }
        
        response = requests.post(f"{self.base_url}/jwt/", json=login_data)
        
        if response.status_code == 200:
            data = response.json()
            self.jwt_token = data.get("access")
            self.headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json"
            }
            print(f"✅ Login successful! Token: {self.jwt_token[:20]}...")
            return True
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(response.text)
            return False
    
    def test_list_carts(self):
        """Test listing all user carts"""
        print("\n📋 Testing: List all carts")
        
        response = requests.get(f"{self.base_url}/carts/", headers=self.headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success: {data.get('message', 'Listed carts')}")
            
            carts = data.get('data', {}).get('carts', [])
            summary = data.get('data', {}).get('summary', {})
            
            print(f"   Total carts: {summary.get('total_carts', 0)}")
            print(f"   Max allowed: {summary.get('max_carts_allowed', 0)}")
            print(f"   Can create more: {summary.get('can_create_more', False)}")
            
            return carts
        else:
            print(f"❌ Failed: {response.status_code}")
            print(response.text)
            return []
    
    def test_create_cart(self, store_id, store_name):
        """Test creating a new cart for a store"""
        print(f"\n🛒 Testing: Create cart for {store_id}")
        
        cart_data = {
            "store_id": store_id,
            "store_name": store_name
        }
        
        response = requests.post(f"{self.base_url}/carts/", json=cart_data, headers=self.headers)
        
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✅ Success: {data.get('message', 'Cart created')}")
            return data.get('data')
        else:
            data = response.json()
            print(f"❌ Failed: {data.get('message', 'Unknown error')}")
            return None
    
    def test_get_cart_by_store(self, store_id):
        """Test getting cart by store ID"""
        print(f"\n🔍 Testing: Get cart for store {store_id}")
        
        response = requests.get(f"{self.base_url}/carts/store/{store_id}/", headers=self.headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success: {data.get('message', 'Cart found')}")
            return data.get('data')
        else:
            data = response.json()
            print(f"❌ Failed: {data.get('message', 'Cart not found')}")
            return None
    
    def test_add_item_to_cart(self, store_id, product_data):
        """Test adding item to cart"""
        print(f"\n➕ Testing: Add item to cart for {store_id}")
        
        item_data = {
            "store_id": store_id,
            **product_data
        }
        
        response = requests.post(f"{self.base_url}/cart/items/", json=item_data, headers=self.headers)
        
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✅ Success: {data.get('message', 'Item added')}")
            return data.get('data')
        else:
            data = response.json()
            print(f"❌ Failed: {data.get('message', 'Failed to add item')}")
            return None
    
    def test_list_cart_items(self, store_id=None):
        """Test listing cart items"""
        print(f"\n📦 Testing: List cart items" + (f" for {store_id}" if store_id else " (all stores)"))
        
        url = f"{self.base_url}/cart/items/"
        if store_id:
            url += f"?store_id={store_id}"
        
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success: {data.get('message', 'Items listed')}")
            return data.get('data')
        else:
            data = response.json()
            print(f"❌ Failed: {data.get('message', 'Failed to list items')}")
            return None
    
    def test_clear_cart(self, store_id=None):
        """Test clearing cart"""
        print(f"\n🗑️ Testing: Clear cart" + (f" for {store_id}" if store_id else " (all carts)"))
        
        url = f"{self.base_url}/cart/clear/"
        if store_id:
            url += f"?store_id={store_id}"
        
        response = requests.delete(url, headers=self.headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Success: {data.get('message', 'Cart cleared')}")
            return True
        else:
            data = response.json()
            print(f"❌ Failed: {data.get('message', 'Failed to clear cart')}")
            return False
    
    def test_cart_limit(self):
        """Test cart creation limit"""
        print(f"\n⚠️ Testing: Cart creation limit")
        
        # Try to create 7 carts (should hit limit at 6th)
        for i in range(7):
            store_id = f"TESTSTORE{i+1:03d}"
            store_name = f"Test Store {i+1}"
            
            result = self.test_create_cart(store_id, store_name)
            if result is None:
                print(f"   Limit reached at store {i+1}")
                break
    
    def run_full_test(self):
        """Run complete API test suite"""
        print("🚀 Starting S2Cart Multi-Store Cart API Tests")
        print("=" * 60)
        
        # Step 1: Login
        if not self.login():
            print("❌ Cannot proceed without login")
            sys.exit(1)
        
        # Step 2: List existing carts
        existing_carts = self.test_list_carts()
        
        # Step 3: Create test carts
        test_stores = [
            {"store_id": "ELECTRONICS001", "store_name": "Electronics Mega Store"},
            {"store_id": "FASHION001", "store_name": "Fashion Hub"},
            {"store_id": "GROCERY001", "store_name": "Fresh Grocery"}
        ]
        
        for store in test_stores:
            self.test_create_cart(store["store_id"], store["store_name"])
        
        # Step 4: Test getting cart by store
        self.test_get_cart_by_store("ELECTRONICS001")
        
        # Step 5: Add items to carts
        test_products = [
            {
                "store_id": "ELECTRONICS001",
                "product_id": "PHONE001",
                "product_name": "iPhone 15 Pro",
                "quantity": 1,
                "unit_price": "1199.00",
                "product_variant": {"color": "Blue", "storage": "256GB"}
            },
            {
                "store_id": "FASHION001",
                "product_id": "SHIRT001",
                "product_name": "Cotton T-Shirt",
                "quantity": 2,
                "unit_price": "29.99",
                "product_variant": {"size": "M", "color": "Red"}
            }
        ]
        
        for product in test_products:
            store_id = product.pop("store_id")
            self.test_add_item_to_cart(store_id, product)
        
        # Step 6: List all cart items
        self.test_list_cart_items()
        
        # Step 7: List items for specific store
        self.test_list_cart_items("ELECTRONICS001")
        
        # Step 8: Test cart limits
        self.test_cart_limit()
        
        # Step 9: Clear specific cart
        self.test_clear_cart("GROCERY001")
        
        # Step 10: Final cart list
        self.test_list_carts()
        
        print("\n" + "=" * 60)
        print("🎉 API Testing Complete!")
        print("\nNote: Some test carts may remain in your account.")
        print("You can clear them using the clear cart endpoints.")

def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(__doc__)
        return
    
    print("S2Cart Multi-Store Cart API Production Tester")
    print("=" * 50)
    print(f"Testing against: {BASE_URL}")
    print(f"Using credentials: {USERNAME}")
    print()
    
    # Check if requests is available
    try:
        import requests
    except ImportError:
        print("❌ Error: 'requests' library not found.")
        print("Install it with: pip install requests")
        sys.exit(1)
    
    tester = S2CartAPITester()
    
    try:
        tester.run_full_test()
    except KeyboardInterrupt:
        print("\n\n⏹️ Test interrupted by user")
    except Exception as e:
        print(f"\n\n💥 Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
