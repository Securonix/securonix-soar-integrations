import pytest
from unittest.mock import patch, MagicMock
from app.forcepoint_swg import ForcepointSwg
from app.model.request_body import RequestBody


@pytest.fixture
def client():
    return ForcepointSwg()


@pytest.fixture
def connection_params():
    return {
        "server_url": "https://ws-custom-categories.api.forcepoint.io/v1.0.0",
        "token_url": "https://api.forcepoint.io/api/apikeys/token",
        "api_key": "test-api-key-123"
    }


def make_request(connection_params, parameters=None):
    request = MagicMock(spec=RequestBody)
    request.connectionParameters = connection_params
    request.parameters = parameters or {}
    return request


def mock_token_response():
    return MagicMock(status_code=200, json=lambda: {"token": "generated-bearer-token"})


class TestTestConnection:

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_success(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"totalResults": 0, "categories": []})
        result = client.test_connection(connection_params)
        assert result['status'] == 'success'

    @patch('app.forcepoint_swg.requests.post')
    def test_token_failure(self, mock_post, client, connection_params):
        mock_post.return_value = MagicMock(status_code=401, text='Unauthorized')
        with pytest.raises(Exception, match='Token generation failed'):
            client.test_connection(connection_params)

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_auth_failure(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_get.return_value = MagicMock(status_code=403, text='Forbidden')
        with pytest.raises(Exception, match='Authentication failed'):
            client.test_connection(connection_params)


class TestGetAllCustomCategories:

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_single_page(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "totalResults": 1,
                "nextPageCursor": None,
                "categories": [{"id": 1, "name": "Blocked Sites"}]
            }
        )
        request = make_request(connection_params)
        result = client.get_all_custom_categories(request)
        assert result['status'] == 'success'
        assert result['totalResults'] == 1
        assert result['categories'][0]['name'] == 'Blocked Sites'

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_pagination(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        page1 = MagicMock(status_code=200, json=lambda: {
            "totalResults": 2,
            "nextPageCursor": "abc",
            "categories": [{"id": 1}]
        })
        page2 = MagicMock(status_code=200, json=lambda: {
            "totalResults": 2,
            "nextPageCursor": None,
            "categories": [{"id": 2}]
        })
        mock_get.side_effect = [page1, page2]
        request = make_request(connection_params)
        result = client.get_all_custom_categories(request)
        assert result['totalResults'] == 2

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_error(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_get.return_value = MagicMock(status_code=500, text='Server error')
        request = make_request(connection_params)
        with pytest.raises(Exception, match='Server error'):
            client.get_all_custom_categories(request)


class TestCreateCategory:

    @patch('app.forcepoint_swg.requests.post')
    def test_success(self, mock_post, client, connection_params):
        token_resp = mock_token_response()
        create_resp = MagicMock(
            status_code=201,
            json=lambda: {
                "transactionId": "00000000-0000-0000-0000-000000000001",
                "status": "pending",
                "data": {},
                "comment": "Created via API"
            }
        )
        mock_post.side_effect = [token_resp, create_resp]
        request = make_request(connection_params, {
            "name": "New Category",
            "description": "Test desc",
            "sites": ["example.com"],
            "policyName": "Default",
            "comment": "Created via API"
        })
        result = client.create_category(request)
        assert result['status'] == 'success'
        assert result['transactionId'] == '00000000-0000-0000-0000-000000000001'
        assert result['transactionStatus'] == 'pending'

    @patch('app.forcepoint_swg.requests.post')
    def test_minimal_params(self, mock_post, client, connection_params):
        token_resp = mock_token_response()
        create_resp = MagicMock(
            status_code=201,
            json=lambda: {
                "transactionId": "00000000-0000-0000-0000-000000000002",
                "status": "pending",
                "data": {},
                "comment": None
            }
        )
        mock_post.side_effect = [token_resp, create_resp]
        request = make_request(connection_params, {"name": "Minimal"})
        result = client.create_category(request)
        assert result['status'] == 'success'
        assert result['transactionId'] is not None

    @patch('app.forcepoint_swg.requests.post')
    def test_error(self, mock_post, client, connection_params):
        token_resp = mock_token_response()
        create_resp = MagicMock(status_code=400, text='Bad request')
        mock_post.side_effect = [token_resp, create_resp]
        request = make_request(connection_params, {"name": "Bad"})
        with pytest.raises(Exception, match='Bad request'):
            client.create_category(request)


class TestGetCategoryById:

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_success(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "id": 5,
                "name": "Test",
                "description": "Test category",
                "policyName": "Default",
                "sites": [{"url": "a.com"}, {"url": "b.com"}],
                "nextPageCursor": None
            }
        )
        request = make_request(connection_params, {"categoryId": 5})
        result = client.get_category_by_id(request)
        assert result['status'] == 'success'
        assert result['category']['id'] == 5
        assert len(result['category']['sites']) == 2

    @patch('app.forcepoint_swg.requests.get')
    @patch('app.forcepoint_swg.requests.post')
    def test_not_found(self, mock_post, mock_get, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_get.return_value = MagicMock(status_code=404, text='Not found')
        request = make_request(connection_params, {"categoryId": 999})
        with pytest.raises(Exception, match='Not found'):
            client.get_category_by_id(request)


class TestAddOrRemoveCategorySites:

    @patch('app.forcepoint_swg.requests.patch')
    @patch('app.forcepoint_swg.requests.post')
    def test_add_sites(self, mock_post, mock_patch, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_patch.return_value = MagicMock(
            status_code=202,
            json=lambda: {
                "transactionId": "00000000-0000-0000-0000-000000000003",
                "status": "pending",
                "data": {},
                "comment": None
            }
        )
        request = make_request(connection_params, {
            "categoryId": 5,
            "action": "add",
            "sites": ["new-site.com"]
        })
        result = client.add_or_remove_category_sites(request)
        assert result['status'] == 'success'
        assert result['transactionId'] == '00000000-0000-0000-0000-000000000003'
        assert result['transactionStatus'] == 'pending'

    @patch('app.forcepoint_swg.requests.patch')
    @patch('app.forcepoint_swg.requests.post')
    def test_remove_sites(self, mock_post, mock_patch, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_patch.return_value = MagicMock(
            status_code=202,
            json=lambda: {
                "transactionId": "00000000-0000-0000-0000-000000000004",
                "status": "pending",
                "data": {},
                "comment": "Removing old site"
            }
        )
        request = make_request(connection_params, {
            "categoryId": 5,
            "action": "remove",
            "sites": ["old-site.com"],
            "comment": "Removing old site"
        })
        result = client.add_or_remove_category_sites(request)
        assert result['status'] == 'success'
        assert result['transactionStatus'] == 'pending'

    @patch('app.forcepoint_swg.requests.patch')
    @patch('app.forcepoint_swg.requests.post')
    def test_error(self, mock_post, mock_patch, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_patch.return_value = MagicMock(status_code=403, text='Forbidden')
        request = make_request(connection_params, {
            "categoryId": 5,
            "action": "add",
            "sites": ["x.com"]
        })
        with pytest.raises(Exception, match='Forbidden'):
            client.add_or_remove_category_sites(request)


class TestDeleteCategory:

    @patch('app.forcepoint_swg.requests.delete')
    @patch('app.forcepoint_swg.requests.post')
    def test_success(self, mock_post, mock_delete, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_delete.return_value = MagicMock(
            status_code=202,
            json=lambda: {
                "transactionId": "00000000-0000-0000-0000-000000000005",
                "status": "pending",
                "data": {},
                "comment": None
            }
        )
        request = make_request(connection_params, {"categoryId": 5})
        result = client.delete_category(request)
        assert result['status'] == 'success'
        assert result['transactionId'] == '00000000-0000-0000-0000-000000000005'
        assert result['transactionStatus'] == 'pending'

    @patch('app.forcepoint_swg.requests.delete')
    @patch('app.forcepoint_swg.requests.post')
    def test_not_found(self, mock_post, mock_delete, client, connection_params):
        mock_post.return_value = mock_token_response()
        mock_delete.return_value = MagicMock(status_code=404, text='Not found')
        request = make_request(connection_params, {"categoryId": 999})
        with pytest.raises(Exception, match='Not found'):
            client.delete_category(request)
