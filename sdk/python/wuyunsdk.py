# sdk/python/platform_sdk/__init__.py
import requests
import json

class PlatformSDK:
    def __init__(self, base_url, app_id=None, app_secret=None):
        self.base_url = base_url
        self.app_id = app_id
        self.app_secret = app_secret
        self.token = None
        
    def set_token(self, token):
        self.token = token
        
    def login(self, username, password):
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={
                "username": username,
                "password": password
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get('token')
            return data
        else:
            raise Exception(f"登录失败: {response.text}")
    
    def register(self, username, password, email):
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={
                "username": username,
                "password": password,
                "email": email
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get('token')
            return data
        else:
            raise Exception(f"注册失败: {response.text}")
    
    def get_user_profile(self, user_id):
        if not self.token:
            raise Exception("请先登录")
            
        response = requests.get(
            f"{self.base_url}/user/{user_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        return response.json()
    
    def create_payment(self, user_id, amount, currency, description=None):
        if not self.token:
            raise Exception("请先登录")
            
        response = requests.post(
            f"{self.base_url}/payment/create",
            json={
                "user_id": user_id,
                "amount": amount,
                "currency": currency,
                "description": description
            },
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        return response.json()
    
    def get_payment_status(self, payment_id):
        if not self.token:
            raise Exception("请先登录")
            
        response = requests.get(
            f"{self.base_url}/payment/{payment_id}/status",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        return response.json()
    
    def get_user_stats(self, start_date=None, end_date=None):
        if not self.token:
            raise Exception("请先登录")
            
        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
            
        response = requests.get(
            f"{self.base_url}/backstage/users/stats",
            params=params,
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        return response.json()
    
    def get_payment_stats(self, start_date=None, end_date=None):
        if not self.token:
            raise Exception("请先登录")
            
        params = {}
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
            
        response = requests.get(
            f"{self.base_url}/backstage/payments/stats",
            params=params,
            headers={"Authorization": f"Bearer {self.token}"}
        )
        
        return response.json()

# 使用示例
if __name__ == "__main__":
    sdk = PlatformSDK("http://localhost:8080")
    
    # 登录
    result = sdk.login("testuser", "password")
    print("登录结果:", result)
    
    # 获取用户统计
    stats = sdk.get_user_stats()
    print("用户统计:", stats)
    
    # 创建支付订单
    payment = sdk.create_payment(1, 100.0, "USD", "测试支付")
    print("支付订单:", payment)