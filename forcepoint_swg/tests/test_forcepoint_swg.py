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
        "server_url": "https://api.forcepoint.example.com/swg/v1",
        "api_key": "test-api-key-123"
    }


def make_request(connection_params, parameters=None):
    request = MagicMock(spec=RequestBody)
    request.connectionParameters = connection_params
    request.parameters = parameters or {}
    return request


class TestTestConnection:

    @patch('app.forcepoint_swg.requests.get')
    def test_success(self, mock_get, client, connection_params):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: [])
        result = client.test_connection(connection_params)
        assert result['status'] == 'success'

    @patch('app.forcepoint_swg.requests.get')
    def test_failure(self, mock_get, client, connection_params):
        mock_get.return_value = MagicMock(status_code=401, text='Unauthorized')
        with pytest.raises(Exception, match='Unauthorized'):
            client.test_connection(connection_params)


class TestGetAllCustomCategories:

    @patch('app.forcepoint_swg.requests.get')
    def test_single_page(self, mock_get, client, connection_params):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: [{"id": 1, "name": "Blocked Sites"}]
        )
        request = make_request(connection_params)
        result = client.get_all_custom_categories(request)
        assert result['status'] == 'success'
        assert result['count'] == 1
        assert result['categories'][0]['name'] == 'Blocked Sites'

    @patch('app.forcepoint_swg.requests.get')
    def test_pagination(self, mock_get, client, connection_params):
        page1 = MagicMock(status_code=200, json=lambda: {"data": [{"id": 1}], "cursor": "abc"})
        page2 = MagicMock(status_code=200, json=lambda: {"data": [{"id": 2}], "cursor": None})
        mock_get.side_effect = [page1, page2]
        request = make_request(connection_params)
        result = client.get_all_custom_categories(request)
        assert result['count'] == 2

    @patch('app.forcepoint_swg.requests.get')
    def test_error(self, mock_get, client, connection_params):
        mock_get.return_value = MagicMock(status_code=500, text='Server error')
        request = make_request(connection_params)
        with pytest.raises(Exception, match='Server error'):
            client.get_all_custom_categories(request)


class TestCreateCategory:

    @patch('app.forcepoint_swg.requests.post')
    def test_success(self, mock_post, client, connection_params):
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"id": 10, "name": "New Category"}
        )
        request = make_request(connection_params, {
            "name": "New Category",
            "description": "Test desc",
            "sites": ["example.com"],
            "policyName": "Default",
            "comment": "Created via API"
        })
        result = client.create_category(request)
        assert result['status'] == 'success'
        assert result['category']['name'] == 'New Category'

    @patch('app.forcepoint_swg.requests.post')
    def test_minimal_params(self, mock_post, client, connection_params):
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"id": 11, "name": "Minimal"}
        )
        request = make_request(connection_params, {"name": "Minimal"})
        result = client.create_category(request)
        assert result['status'] == 'success'

    @patch('app.forcepoint_swg.requests.post')
    def test_error(self, mock_post, client, connection_params):
        mock_post.return_value = MagicMock(status_code=400, text='Bad request')
        request = make_request(connection_params, {"name": "Bad"})
        with pytest.raises(Exception, match='Bad request'):
            client.create_category(request)


class TestGetCategoryById:

    @patch('app.forcepoint_swg.requests.get')
    def test_success(self, mock_get, client, connection_params):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"id": 5, "name": "Test", "sites": ["a.com", "b.com"]}
        )
        request = make_request(connection_params, {"categoryId": 5})
        result = client.get_category_by_id(request)
        assert result['status'] == 'success'
        assert result['category']['id'] == 5
        assert len(result['category']['sites']) == 2

    @patch('app.forcepoint_swg.requests.get')
    def test_not_found(self, mock_get, client, connection_params):
        mock_get.return_value = MagicMock(status_code=404, text='Not found')
        request = make_request(connection_params, {"categoryId": 999})
        with pytest.raises(Exception, match='Not found'):
            client.get_category_by_id(request)


class TestAddOrRemoveCategorySites:

    @patch('app.forcepoint_swg.requests.patch')
    def test_add_sites(self, mock_patch, client, connection_params):
        mock_patch.return_value = MagicMock(status_code=202)
        request = make_request(connection_params, {
            "categoryId": 5,
            "action": "add",
            "sites": ["new-site.com"]
        })
        result = client.add_or_remove_category_sites(request)
        assert result['status'] == 'success'
        assert result['action'] == 'add'

    @patch('app.forcepoint_swg.requests.patch')
    def test_remove_sites(self, mock_patch, client, connection_params):
        mock_patch.return_value = MagicMock(status_code=202)
        request = make_request(connection_params, {
            "categoryId": 5,
            "action": "remove",
            "sites": ["old-site.com"],
            "comment": "Removing old site"
        })
        result = client.add_or_remove_category_sites(request)
        assert result['status'] == 'success'
        assert result['action'] == 'remove'

    @patch('app.forcepoint_swg.requests.patch')
    def test_error(self, mock_patch, client, connection_params):
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
    def test_success(self, mock_delete, client, connection_params):
        mock_delete.return_value = MagicMock(status_code=202)
        request = make_request(connection_params, {"categoryId": 5})
        result = client.delete_category(request)
        assert result['status'] == 'success'
        assert result['categoryId'] == 5

    @patch('app.forcepoint_swg.requests.delete')
    def test_not_found(self, mock_delete, client, connection_params):
        mock_delete.return_value = MagicMock(status_code=404, text='Not found')
        request = make_request(connection_params, {"categoryId": 999})
        with pytest.raises(Exception, match='Not found'):
            client.delete_category(request)
