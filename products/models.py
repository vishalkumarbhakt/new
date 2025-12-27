from django.db import models
from django.conf import settings
from django.utils.text import slugify
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from decimal import Decimal
import uuid


class Category(models.Model):
    """
    Category model for organizing products with hierarchical structure.
    """
    name = models.CharField(max_length=255, help_text="Category name")
    slug = models.SlugField(max_length=255, unique=True, help_text="SEO-friendly URL slug")
    description = models.TextField(blank=True, null=True, help_text="Category description")
    image = models.ImageField(upload_to='categories/', blank=True, null=True, help_text="Category image")
    
    # Hierarchical structure
    parent = models.ForeignKey(
        'self', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True, 
        related_name='subcategories',
        help_text="Parent category for hierarchy"
    )
    
    # Display and ordering
    display_order = models.PositiveIntegerField(default=0, help_text="Order for display")
    is_active = models.BooleanField(default=True, help_text="Whether category is visible to customers")
    is_featured = models.BooleanField(default=False, help_text="Featured category for homepage")
    
    # SEO fields
    meta_title = models.CharField(max_length=255, blank=True, null=True, help_text="SEO meta title")
    meta_description = models.TextField(blank=True, null=True, help_text="SEO meta description")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = "Categories"
        ordering = ['display_order', 'name']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['is_active']),
            models.Index(fields=['parent']),
            models.Index(fields=['display_order']),
        ]
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
            # Ensure unique slug
            original_slug = self.slug
            counter = 1
            while Category.objects.filter(slug=self.slug).exclude(pk=self.pk).exists():
                self.slug = f"{original_slug}-{counter}"
                counter += 1
        super().save(*args, **kwargs)
    
    @property
    def full_path(self):
        """Get full category path (e.g., 'Electronics > Mobiles > Smartphones')"""
        path = [self.name]
        parent = self.parent
        while parent:
            path.insert(0, parent.name)
            parent = parent.parent
        return ' > '.join(path)
    
    @property
    def product_count(self):
        """Get count of active products in this category"""
        return self.products.filter(is_active=True).count()


class Product(models.Model):
    """
    Product model representing items for sale.
    """
    # Basic Information
    name = models.CharField(max_length=255, help_text="Product name")
    slug = models.SlugField(max_length=255, unique=True, help_text="SEO-friendly URL slug")
    sku = models.CharField(max_length=100, unique=True, help_text="Stock Keeping Unit")
    description = models.TextField(blank=True, null=True, help_text="Product description")
    short_description = models.CharField(max_length=500, blank=True, null=True, help_text="Short description for listings")
    
    # Category relationship
    category = models.ForeignKey(
        Category, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='products',
        help_text="Product category"
    )
    
    # Pricing
    price = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        validators=[MinValueValidator(Decimal('0.01'))],
        help_text="Regular price in INR"
    )
    discount_price = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        null=True, 
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Discounted price (if applicable)"
    )
    discount_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        null=True, 
        blank=True,
        validators=[MinValueValidator(Decimal('0')), MaxValueValidator(Decimal('100'))],
        help_text="Discount percentage for display"
    )
    
    # Inventory
    stock_quantity = models.PositiveIntegerField(default=0, help_text="Available stock quantity")
    low_stock_threshold = models.PositiveIntegerField(default=10, help_text="Low stock alert threshold")
    is_track_stock = models.BooleanField(default=True, help_text="Whether to track inventory")
    allow_backorder = models.BooleanField(default=False, help_text="Allow orders when out of stock")
    
    # Product Details
    weight = models.DecimalField(
        max_digits=10, 
        decimal_places=3, 
        null=True, 
        blank=True,
        help_text="Weight in kg"
    )
    dimensions = models.JSONField(
        null=True, 
        blank=True,
        help_text="Product dimensions (length, width, height in cm)"
    )
    brand = models.CharField(max_length=100, blank=True, null=True, help_text="Product brand")
    
    # Attributes and Variants
    attributes = models.JSONField(
        null=True, 
        blank=True,
        help_text="Product attributes (color, size, material, etc.)"
    )
    variants = models.JSONField(
        null=True, 
        blank=True,
        help_text="Product variants with pricing"
    )
    
    # Visibility and Status
    is_active = models.BooleanField(default=True, help_text="Whether product is visible to customers")
    is_featured = models.BooleanField(default=False, help_text="Featured product for promotions")
    is_new = models.BooleanField(default=True, help_text="Mark as new arrival")
    is_bestseller = models.BooleanField(default=False, help_text="Mark as bestseller")
    
    # SEO fields
    meta_title = models.CharField(max_length=255, blank=True, null=True, help_text="SEO meta title")
    meta_description = models.TextField(blank=True, null=True, help_text="SEO meta description")
    meta_keywords = models.CharField(max_length=500, blank=True, null=True, help_text="SEO keywords")
    
    # Tax and Shipping
    tax_class = models.CharField(
        max_length=50,
        choices=[
            ('STANDARD', 'Standard GST'),
            ('REDUCED', 'Reduced GST'),
            ('ZERO', 'Zero GST'),
            ('EXEMPT', 'GST Exempt'),
        ],
        default='STANDARD',
        help_text="Tax classification"
    )
    is_digital = models.BooleanField(default=False, help_text="Digital product (no shipping)")
    
    # Statistics
    view_count = models.PositiveIntegerField(default=0, help_text="Number of product views")
    sold_count = models.PositiveIntegerField(default=0, help_text="Number of units sold")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True, help_text="When product was published")
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['sku']),
            models.Index(fields=['is_active']),
            models.Index(fields=['is_featured']),
            models.Index(fields=['category']),
            models.Index(fields=['price']),
            models.Index(fields=['stock_quantity']),
            models.Index(fields=['created_at']),
            models.Index(fields=['sold_count']),
        ]
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        # Auto-generate slug
        if not self.slug:
            self.slug = slugify(self.name)
            original_slug = self.slug
            counter = 1
            while Product.objects.filter(slug=self.slug).exclude(pk=self.pk).exists():
                self.slug = f"{original_slug}-{counter}"
                counter += 1
        
        # Auto-generate SKU if not provided
        if not self.sku:
            self.sku = f"SKU-{uuid.uuid4().hex[:8].upper()}"
        
        # Calculate discount percentage if discount_price is set
        if self.discount_price and self.price and self.discount_price < self.price:
            self.discount_percentage = ((self.price - self.discount_price) / self.price) * 100
        
        # Set published_at when first activated
        if self.is_active and not self.published_at:
            self.published_at = timezone.now()
        
        super().save(*args, **kwargs)
    
    @property
    def effective_price(self):
        """Get the effective selling price (discount price if available, else regular price)"""
        if self.discount_price and self.discount_price < self.price:
            return self.discount_price
        return self.price
    
    @property
    def is_on_sale(self):
        """Check if product is on sale"""
        return self.discount_price is not None and self.discount_price < self.price
    
    @property
    def is_in_stock(self):
        """Check if product is in stock"""
        if not self.is_track_stock:
            return True
        if self.allow_backorder:
            return True
        return self.stock_quantity > 0
    
    @property
    def is_low_stock(self):
        """Check if product is low on stock"""
        if not self.is_track_stock:
            return False
        return 0 < self.stock_quantity <= self.low_stock_threshold
    
    @property
    def primary_image(self):
        """Get primary product image"""
        image = self.images.filter(is_primary=True).first()
        if not image:
            image = self.images.first()
        return image
    
    @property
    def savings_amount(self):
        """Calculate savings amount"""
        if self.is_on_sale:
            return self.price - self.discount_price
        return Decimal('0.00')
    
    def decrement_stock(self, quantity):
        """Decrease stock quantity when order is placed"""
        if self.is_track_stock:
            self.stock_quantity = max(0, self.stock_quantity - quantity)
            self.sold_count += quantity
            self.save(update_fields=['stock_quantity', 'sold_count'])
    
    def increment_stock(self, quantity):
        """Increase stock quantity (e.g., for returns or restocking)"""
        if self.is_track_stock:
            self.stock_quantity += quantity
            self.save(update_fields=['stock_quantity'])
    
    def increment_view_count(self):
        """Increment view count"""
        self.view_count += 1
        self.save(update_fields=['view_count'])


class ProductImage(models.Model):
    """
    Product image model for multiple product images.
    """
    product = models.ForeignKey(
        Product, 
        on_delete=models.CASCADE, 
        related_name='images',
        help_text="Product this image belongs to"
    )
    image = models.ImageField(upload_to='products/', help_text="Product image file")
    alt_text = models.CharField(max_length=255, blank=True, null=True, help_text="Alternative text for accessibility")
    is_primary = models.BooleanField(default=False, help_text="Primary image for product listing")
    display_order = models.PositiveIntegerField(default=0, help_text="Order for display")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-is_primary', 'display_order']
        indexes = [
            models.Index(fields=['product', 'is_primary']),
            models.Index(fields=['display_order']),
        ]
    
    def __str__(self):
        return f"Image for {self.product.name}"
    
    def save(self, *args, **kwargs):
        # If this is set as primary, unset other primary images
        if self.is_primary:
            ProductImage.objects.filter(
                product=self.product, 
                is_primary=True
            ).exclude(pk=self.pk).update(is_primary=False)
        
        # If this is the first image, make it primary
        if not ProductImage.objects.filter(product=self.product).exclude(pk=self.pk).exists():
            self.is_primary = True
        
        super().save(*args, **kwargs)


class ProductReview(models.Model):
    """
    Product review model for customer reviews.
    """
    product = models.ForeignKey(
        Product, 
        on_delete=models.CASCADE, 
        related_name='reviews',
        help_text="Product being reviewed"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='product_reviews',
        help_text="User who wrote the review"
    )
    
    rating = models.PositiveIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Rating from 1 to 5"
    )
    title = models.CharField(max_length=255, blank=True, null=True, help_text="Review title")
    comment = models.TextField(blank=True, null=True, help_text="Review comment")
    
    # Review status
    is_verified_purchase = models.BooleanField(default=False, help_text="Whether user purchased the product")
    is_approved = models.BooleanField(default=True, help_text="Whether review is approved for display")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        unique_together = ['product', 'user']
        indexes = [
            models.Index(fields=['product', 'is_approved']),
            models.Index(fields=['rating']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Review by {self.user.username} for {self.product.name}"


class Wishlist(models.Model):
    """
    Wishlist model for user saved products.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='wishlists',
        help_text="User who owns the wishlist"
    )
    product = models.ForeignKey(
        Product, 
        on_delete=models.CASCADE, 
        related_name='wishlisted_by',
        help_text="Product in wishlist"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['user', 'product']
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'product']),
        ]
    
    def __str__(self):
        return f"{self.user.username}'s wishlist item: {self.product.name}"
