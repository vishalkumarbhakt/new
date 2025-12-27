from rest_framework import serializers
from django.utils.text import slugify
from .models import Category, Product, ProductImage, ProductReview, Wishlist


class CategorySerializer(serializers.ModelSerializer):
    """Serializer for Category model"""
    product_count = serializers.ReadOnlyField()
    full_path = serializers.ReadOnlyField()
    subcategories = serializers.SerializerMethodField()
    
    class Meta:
        model = Category
        fields = (
            'id', 'name', 'slug', 'description', 'image', 'parent',
            'display_order', 'is_active', 'is_featured', 'meta_title',
            'meta_description', 'product_count', 'full_path', 'subcategories',
            'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'slug', 'created_at', 'updated_at')
    
    def get_subcategories(self, obj):
        """Get active subcategories"""
        subcategories = obj.subcategories.filter(is_active=True)
        return CategoryBasicSerializer(subcategories, many=True).data


class CategoryBasicSerializer(serializers.ModelSerializer):
    """Basic serializer for Category (used in nested representations)"""
    product_count = serializers.ReadOnlyField()
    
    class Meta:
        model = Category
        fields = ('id', 'name', 'slug', 'image', 'product_count')


class CategoryCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating categories (admin only)"""
    
    class Meta:
        model = Category
        fields = (
            'name', 'description', 'image', 'parent', 'display_order',
            'is_active', 'is_featured', 'meta_title', 'meta_description'
        )
    
    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Category name is required")
        return value.strip()


class ProductImageSerializer(serializers.ModelSerializer):
    """Serializer for ProductImage model"""
    image_url = serializers.SerializerMethodField()
    
    class Meta:
        model = ProductImage
        fields = ('id', 'image', 'image_url', 'alt_text', 'is_primary', 'display_order')
        read_only_fields = ('id',)
    
    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image and request:
            return request.build_absolute_uri(obj.image.url)
        elif obj.image:
            return obj.image.url
        return None


class ProductListSerializer(serializers.ModelSerializer):
    """Serializer for product listing (minimal data for performance)"""
    category_name = serializers.CharField(source='category.name', read_only=True)
    primary_image = serializers.SerializerMethodField()
    effective_price = serializers.ReadOnlyField()
    is_on_sale = serializers.ReadOnlyField()
    is_in_stock = serializers.ReadOnlyField()
    savings_amount = serializers.ReadOnlyField()
    average_rating = serializers.SerializerMethodField()
    review_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Product
        fields = (
            'id', 'name', 'slug', 'short_description', 'category', 'category_name',
            'price', 'discount_price', 'discount_percentage', 'effective_price',
            'is_on_sale', 'savings_amount', 'is_in_stock', 'stock_quantity',
            'is_featured', 'is_new', 'is_bestseller', 'brand',
            'primary_image', 'average_rating', 'review_count'
        )
    
    def get_primary_image(self, obj):
        image = obj.primary_image
        if image:
            return ProductImageSerializer(image, context=self.context).data
        return None
    
    def get_average_rating(self, obj):
        reviews = obj.reviews.filter(is_approved=True)
        if reviews.exists():
            return round(sum(r.rating for r in reviews) / reviews.count(), 1)
        return None
    
    def get_review_count(self, obj):
        return obj.reviews.filter(is_approved=True).count()


class ProductDetailSerializer(serializers.ModelSerializer):
    """Serializer for product detail view (full data)"""
    category = CategoryBasicSerializer(read_only=True)
    images = ProductImageSerializer(many=True, read_only=True)
    effective_price = serializers.ReadOnlyField()
    is_on_sale = serializers.ReadOnlyField()
    is_in_stock = serializers.ReadOnlyField()
    is_low_stock = serializers.ReadOnlyField()
    savings_amount = serializers.ReadOnlyField()
    average_rating = serializers.SerializerMethodField()
    review_count = serializers.SerializerMethodField()
    reviews = serializers.SerializerMethodField()
    related_products = serializers.SerializerMethodField()
    
    class Meta:
        model = Product
        fields = (
            'id', 'name', 'slug', 'sku', 'description', 'short_description',
            'category', 'price', 'discount_price', 'discount_percentage',
            'effective_price', 'is_on_sale', 'savings_amount',
            'stock_quantity', 'is_in_stock', 'is_low_stock', 'is_track_stock',
            'weight', 'dimensions', 'brand', 'attributes', 'variants',
            'is_active', 'is_featured', 'is_new', 'is_bestseller',
            'meta_title', 'meta_description', 'meta_keywords',
            'tax_class', 'is_digital', 'view_count', 'sold_count',
            'images', 'average_rating', 'review_count', 'reviews',
            'related_products', 'created_at', 'updated_at', 'published_at'
        )
    
    def get_average_rating(self, obj):
        reviews = obj.reviews.filter(is_approved=True)
        if reviews.exists():
            return round(sum(r.rating for r in reviews) / reviews.count(), 1)
        return None
    
    def get_review_count(self, obj):
        return obj.reviews.filter(is_approved=True).count()
    
    def get_reviews(self, obj):
        """Get approved reviews (limited to 5 for initial load)"""
        reviews = obj.reviews.filter(is_approved=True)[:5]
        return ProductReviewSerializer(reviews, many=True, context=self.context).data
    
    def get_related_products(self, obj):
        """Get related products from same category"""
        if obj.category:
            related = Product.objects.filter(
                category=obj.category, 
                is_active=True
            ).exclude(id=obj.id)[:4]
            return ProductListSerializer(related, many=True, context=self.context).data
        return []


class ProductCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating products (admin only)"""
    
    class Meta:
        model = Product
        fields = (
            'name', 'description', 'short_description', 'category',
            'price', 'discount_price', 'stock_quantity', 'low_stock_threshold',
            'is_track_stock', 'allow_backorder', 'weight', 'dimensions',
            'brand', 'attributes', 'variants', 'is_active', 'is_featured',
            'is_new', 'is_bestseller', 'meta_title', 'meta_description',
            'meta_keywords', 'tax_class', 'is_digital'
        )
    
    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Product name is required")
        return value.strip()
    
    def validate_price(self, value):
        if value is None or value < 0.01:
            raise serializers.ValidationError("Price must be at least ₹0.01")
        return value
    
    def validate(self, data):
        # Validate discount price is less than regular price
        price = data.get('price')
        discount_price = data.get('discount_price')
        
        if discount_price and price and discount_price >= price:
            raise serializers.ValidationError({
                'discount_price': 'Discount price must be less than regular price'
            })
        
        return data


class ProductImageCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating product images (admin only)"""
    
    class Meta:
        model = ProductImage
        fields = ('product', 'image', 'alt_text', 'is_primary', 'display_order')
    
    def validate_image(self, value):
        if not value:
            raise serializers.ValidationError("Image file is required")
        return value


class ProductReviewSerializer(serializers.ModelSerializer):
    """Serializer for product reviews"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = ProductReview
        fields = (
            'id', 'product', 'user', 'user_name', 'rating', 'title', 'comment',
            'is_verified_purchase', 'is_approved', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'user', 'is_verified_purchase', 'created_at', 'updated_at')


class ProductReviewCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating product reviews"""
    
    class Meta:
        model = ProductReview
        fields = ('product', 'rating', 'title', 'comment')
    
    def validate_rating(self, value):
        if not 1 <= value <= 5:
            raise serializers.ValidationError("Rating must be between 1 and 5")
        return value
    
    def validate(self, data):
        request = self.context.get('request')
        product = data.get('product')
        
        # Check if user already reviewed this product
        if request and request.user.is_authenticated:
            if ProductReview.objects.filter(
                product=product, 
                user=request.user
            ).exists():
                raise serializers.ValidationError({
                    'product': 'You have already reviewed this product'
                })
        
        return data
    
    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['user'] = request.user
        
        # Check if user purchased this product (simplified check)
        from authentication.models import Order, OrderItem
        is_verified = OrderItem.objects.filter(
            order__user=request.user,
            product_id=str(validated_data['product'].id),
            order__status='DELIVERED'
        ).exists()
        validated_data['is_verified_purchase'] = is_verified
        
        return super().create(validated_data)


class WishlistSerializer(serializers.ModelSerializer):
    """Serializer for wishlist items"""
    product_details = ProductListSerializer(source='product', read_only=True)
    
    class Meta:
        model = Wishlist
        fields = ('id', 'user', 'product', 'product_details', 'created_at')
        read_only_fields = ('id', 'user', 'created_at')


class WishlistCreateSerializer(serializers.ModelSerializer):
    """Serializer for adding items to wishlist"""
    
    class Meta:
        model = Wishlist
        fields = ('product',)
    
    def validate(self, data):
        request = self.context.get('request')
        product = data.get('product')
        
        if request and request.user.is_authenticated:
            if Wishlist.objects.filter(
                product=product,
                user=request.user
            ).exists():
                raise serializers.ValidationError({
                    'product': 'Product is already in your wishlist'
                })
        
        return data
    
    def create(self, validated_data):
        request = self.context.get('request')
        validated_data['user'] = request.user
        return super().create(validated_data)
