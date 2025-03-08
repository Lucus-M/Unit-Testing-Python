# Lucus Mulhorn
# Python Unit Testing
# 3-7-2025
# chatgpt.com used to generate test data

from validate import Validate    # The code to test
import unittest   # The test framework

class Test_TestValidate(unittest.TestCase):
    def test_zip_happy(self):
        #HAPPY PATH
        self.assertTrue(Validate.zip("17701"))

    def test_zip_bad(self):
        #ABUSE
        f = open("blns.payloads", "rb")

        for line in f:
            print(f"Attempting {line}")
            self.assertFalse(Validate.zip(str(line)))
    
    # Test the happy path for age validation (minor check)
    def test_minor_happy(self):
        ages = [16, 17, 1, 4, 6, 2]  # These are minors, so they should return True
        for age in ages:
            with self.subTest(age=age):
                self.assertTrue(Validate.minor(age))

    # Test abuse cases for age validation (should not be minor)
    def test_minor_abuse(self):
        ages = [18, 20, 65]
        for age in ages:
            with self.subTest(age=age):
                self.assertFalse(Validate.minor(age))
    
    # Test the happy path for email validation
    def test_email_happy(self):
        valid_emails = [
            "test@example.com",
            "name.surname@domain.co",
            "user_123@subdomain.domain.com"
        ]
        for email in valid_emails:
            with self.subTest(email=email):
                self.assertTrue(Validate.email(email))

    # Test abuse cases for email validation
    def test_email_abuse(self):
        invalid_emails = [
            "plainaddress",            # No @ symbol or domain
            "@no.domain",              # Missing username before the @ symbol
            "user@com",                # Missing top-level domain (e.g., .com, .org)
            "user@.com",               # Domain starts with a dot
            "user@domain..com",        # Consecutive dots in the domain
            "user@domain.com.",        # Ends with a dot
            "user@@domain.com",        # Double @ symbol
            "",                        # Empty string
            " ",                       # Space (invalid email)
            "user@domain.c",           # Top-level domain too short (less than 2 characters)
            "user@domain.123",         # Non-alphabetic top-level domain (numeric domain)
            "user@-domain.com",        # Domain starts with a hyphen
            "user@domain-.com",        # Domain ends with a hyphen
            "user@doma_in.com",        # Underscore in the domain part
            "user@domain.c..com",      # Double dot in the middle of the domain part
            "user@.domain.com",        # Domain starts with a dot
            "user@domain_com.com",     # Underscore in the domain part
            "user@domain.com..com",    # Double dot in the domain section
        ]
        for email in invalid_emails:
            with self.subTest(email=email):
                self.assertFalse(Validate.email(email))

    # Test the happy path for latitude validation
    def test_latitude_happy(self):
        valid_latitudes = [-90, 0, 45, 90]  # Valid latitude values
        for lat in valid_latitudes:
            with self.subTest(lat=lat):
                self.assertTrue(Validate.is_lat(lat))

    # Test abuse cases for latitude validation
    def test_latitude_abuse(self):
        invalid_latitudes = [-91, 91, "not a number", None, "39", 300]  # Invalid latitudes
        for lat in invalid_latitudes:
            with self.subTest(lat=lat):
                self.assertFalse(Validate.is_lat(lat))

    # Test the happy path for longitude validation
    def test_longitude_happy(self):
        valid_longitudes = [-180, 0, 45, 180]  # Valid longitude values
        for lng in valid_longitudes:
            with self.subTest(lng=lng):
                self.assertTrue(Validate.is_lng(lng))

    # Test abuse cases for longitude validation
    def test_longitude_abuse(self):
        invalid_longitudes = [-181, 181, "not a number", None]  # Invalid longitudes
        for lng in invalid_longitudes:
            with self.subTest(lng=lng):
                self.assertFalse(Validate.is_lng(lng))

    # Test the happy path for domain validation
    def test_domain_happy(self):
        valid_domains = [
            "example.com",             # Standard domain name
            "mywebsite.org",           # Domain with .org extension
            "subdomain.example.net",   # Subdomain with .net extension
            "name123.com",             # Alphanumeric domain
            "valid-domain.co.uk",      # Domain with hyphen and .co.uk extension
            "domain123.io",            # Alphanumeric domain with .io extension
            "company-name.com",        # Domain with hyphen
            "newsite.info",            # Domain with .info extension
            "website.xyz",             # Domain with new extension .xyz
            "example1234.com",         # Alphanumeric domain with numbers
            "my-cool-site.biz"         # Domain with hyphens and .biz extension
        ]

        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(Validate.is_domain(domain))

    # Test abuse cases for domain validation
    def test_domain_abuse(self):
        invalid_domains = [
            "example domain.com",   # Space in domain
            "invalid domain name.net", # Space in domain
            "hello world.org",        # Space in domain
            "example@domain.com",    # "@" in domain
            "my_domain.com",         # Underscore in domain
            "user#name.com",         # Special character "#" in domain
            "-example.com",          # Starting with a hyphen
            "example-.com",          # Ending with a hyphen
            "-domain-.org",          # Starting and ending with a hyphen
            "example..com",          # Double dot
            "my...website.org",      # Multiple consecutive dots
            "site....com",           # Multiple consecutive dots
            "a" * 255 + ".com",      # Domain length exceeds 253 characters
            "longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong.com" # Subdomain length exceeds 63 characters
        ]
        for domain in invalid_domains:
            with self.subTest(domain=domain):
                self.assertFalse(Validate.is_domain(domain))

    # Test the happy path for URL validation
    def test_url_happy(self):
        valid_urls = [
            "http://example.com",
            "https://secure-site.com",
            "http://www.domain.org/path",
            "https://subdomain.example.com",
            "http://example.com:8080",
            "https://example.com?query=value",
            "https://example.net/path/to/resource?key=value#section",
            "https://www.example.co.uk",
            "https://api.example.com/v1/endpoint",
            "https://www.example.net",
            "http://example.org",
            "http://test-domain.com:3000/api/v1",
            "https://new-site123.com",
            "https://example.org/path/to/resource",
            "http://example.io:9000/data",
            "http://test.subdomain.example.com",
            "https://example.com/#about",
            "https://my-website.com",
            "https://example.com/page?item=123&sort=desc",
            "https://13284913849.com",
            "http://example.com/nospace",
            
        ]
        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(Validate.is_url(url))

    # Test abuse cases for URL validation
    def test_url_abuse(self):
        invalid_urls = [
            "plainaddress",        # No URL scheme or domain
            "http://",             # Incomplete URL
            "www.example.net",     # Missing scheme ("http://")
            "ftp://example.com",    # Invalid scheme ("ftp" instead of "http(s)")
            "http://example .org",
            "http://example.com:abcd",
            "http://example@com"
        ]
        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(Validate.is_url(url))

    # Test the happy path for grade validation
    def test_grade_happy(self):
        valid_grades = {
            59: 'F',
            65: 'D',
            75: 'C',
            85: 'B',
            95: 'A'
        }
        for score, expected_grade in valid_grades.items():
            with self.subTest(score=score):
                self.assertEqual(Validate.grade(score), expected_grade)

    # Test abuse cases for grade validation
    def test_grade_abuse(self):
        invalid_scores = [-1, "not a number", None]
        for score in invalid_scores:
            with self.subTest(score=score):
                self.assertEqual(Validate.grade(score), 'F') #return F if invalid
    
    # Test sanitize method (SQL sanitization)
    def test_sanitize_happy(self):
        sql_input = "SELECT * FROM users WHERE username = 'admin' OR 1=1"
        sanitized = Validate.sanitize(sql_input)
        self.assertNotIn("ADMIN", sanitized)  # "ADMIN" should be removed
        self.assertNotIn("OR", sanitized)  # "OR" should be removed

    # Test strip_null method
    def test_strip_null(self):
        input_str = "This is a None test."
        result = Validate.strip_null(input_str)
        self.assertNotIn("None", result)  # "None" should be removed from the string
    
    def test_ip_happy(self):
        valid_ips = [
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255"
        ]

        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(Validate.ip(ip))

    def test_ip_abuse(self):
        invalid_ips = [
            "192.168.1.999",
            "1a92.168.1.1",
            "256.256.256.256",
            "abc.def.ghi.jkl",
            "192.168.1"
        ]

        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(Validate.ip(ip))
    
    def test_mac_happy(self):
        self.assertTrue(Validate.mac("00:1A:2B:3C:4D:5E"))
        self.assertTrue(Validate.mac("00-1A-2B-3C-4D-5E"))
        self.assertTrue(Validate.mac("00 1A 2B 3C 4D 5E"))
        self.assertTrue(Validate.mac("00 00 00 00 00 00"))
    
    def test_mac_abuse(self):
        self.assertFalse(Validate.mac("00:1A:2B:3C:4D"))
        self.assertFalse(Validate.mac("00:1A:2B:3C:4D:GG"))
        self.assertFalse(Validate.mac("00 1A 2B 3C 4D 5E 6F"))
        self.assertFalse(Validate.mac("001A2B3C4D5E"))

    def test_md5_happy(self):
        self.assertTrue(Validate.md5("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertTrue(Validate.md5("098f6bcd4621d373cade4e832627b4f6"))
    
    def test_md5_abuse(self):
        self.assertFalse(Validate.md5("d41d8cd98f00b204e9800998ecf8427"))
        self.assertFalse(Validate.md5("z41d8cd98f00b204e9800998ecf8427e"))
        self.assertFalse(Validate.md5("d41d8cd98f00b204e9800998ecf8427ex"))

if __name__ == '__main__':
    unittest.main()
