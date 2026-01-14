from typing import List, Dict
from tqdm import tqdm
import boto3
from boto3.dynamodb.types import Binary
from preprocessor.convert import int2bits

class Database:
    """
    Wrapper for accessing DynamoDB tables with robust handling of binary data types,
    supporting both production (AWS, DynamoDB Local) and testing environments.
    """

    def __init__(
        self,
        database: str = "testinglocal",
        bitmap_table: str = "cloudEpochBitmapsTable",
        blocksnapshot_table: str = "cloudBlockSnapshotStoreTable",
        endpoint_url: str = "http://localhost:8000"
    ) -> None:
        self.client = boto3.client('dynamodb', endpoint_url=endpoint_url)
        self.resource = boto3.resource('dynamodb', endpoint_url=endpoint_url)
        self.database = database
        self.BITMAP = bitmap_table
        self.BLOCKSNAPSHOT = blocksnapshot_table

    def set_name(self, name: str) -> None:
        self.database = name

    def list_tables(self) -> List[Dict]:
        tables = self.client.list_tables().get("TableNames")
        keys = [i for i in range(len(tables))]
        return [dict(zip(keys, tables))]

    def item(self, bitmap: bool = False, scan: str = "") -> List[Dict]:
        reference_table = f'{self.database}-{self.BITMAP}' if bitmap else f'{self.database}-{self.BLOCKSNAPSHOT}'
        data = list()
        try:
            table = self.resource.Table(reference_table)
            data = table.scan().get('Items')
        except Exception as e:
            print(f"Item was not found on {reference_table} ({e})")
        return data

    def item_by_key(self, key: Dict) -> List[Dict]:
        try:
            table = self.resource.Table(f'{self.database}-{self.BLOCKSNAPSHOT}')
            item = [table.get_item(Key=key).get('Item')]
        except Exception as e:
            print(e)
            item = []
        return item

    def item_by_block(self, block: int) -> List[Dict]:
        try:
            table = self.resource.Table(f'{self.database}-{self.BLOCKSNAPSHOT}')
            epoch = int.from_bytes(table.get_item(Key={"key": "EpochCount"}).get('Item')["value"].value, "big")
            item_block = []
            for i in range(1, epoch + 1):
                response = table.get_item(Key={"key": f'{i}:{block}'}).get('Item')
                if response is not None:
                    item_block.append(response)
        except Exception as e:
            print(e)
            item_block = []
        return item_block

    def _convert_binary_value(self, value):
        """
        Robustly convert a value returned from DynamoDB (possibly a Binary, bytes, bytearray, or list)
        into a Python bytes object.
        """
        if isinstance(value, Binary):
            return bytes(value)
        elif isinstance(value, (bytes, bytearray)):
            return bytes(value)
        elif isinstance(value, list):
            # Assume list of ints (for test environments)
            return bytes(value)
        elif value is None:
            return b""
        else:
            raise TypeError(f"Unexpected type for DynamoDB binary field: {type(value)}")

    def item_bitmap(self, epoch=-1):
        """
        Fetch and decode the bitmap for a given epoch as a list of bits (ints).
        """
        try:
            table = self.resource.Table(f"{self.database}-{self.BITMAP}")
            if epoch == -1:
                return []
            item = table.get_item(Key={"key": f"{epoch}-bitmap"}).get('Item', None)
            if item is None or "value" not in item:
                return []
            value = self._convert_binary_value(item["value"])
            bitmap = []
            for byte in value:
                bitmap += int2bits(byte)
            return bitmap
        except Exception as e:
            print(f"[item_bitmap] Error: {e}")
            return []

    def item_by_epoch(self, epoch: int) -> List[Dict]:
        """
        Return all mutated blocks for a given epoch, robustly handling DynamoDB binary values.
        """
        items = []
        try:
            table_name_bitmap = f"{self.database}-{self.BITMAP}"
            table_name_blocksnapshot = f"{self.database}-{self.BLOCKSNAPSHOT}"

            table = self.resource.Table(table_name_bitmap)
            response = table.get_item(Key={"key": f"{epoch}-bitmap"}).get('Item', None)
            if not response or "value" not in response:
                print(f"[item_by_epoch] No bitmap found for epoch {epoch}")
                return []
            value = self._convert_binary_value(response["value"])
            bitmap = []
            for byte in value:
                bitmap += int2bits(byte)

            table = self.resource.Table(table_name_blocksnapshot)
            bitmap_indices = [i for i, val in enumerate(bitmap) if val == 1]

            for block_id in bitmap_indices:
                item = table.get_item(Key={"key": f"{epoch}:{block_id}"}).get("Item")
                if item is not None:
                    items.append(item)
                else:
                    print(f"[item_by_epoch] No item found for key {epoch}:{block_id}")
        except Exception as e:
            print(f"[ERROR] Exception in item_by_epoch: {e}")
        print(f"[item_by_epoch] Returning {len(items)} items for epoch {epoch}")
        return items

    def get_latest_epoch(self) -> int:
        try:
            table = self.resource.Table(f"{self.database}-{self.BLOCKSNAPSHOT}")
            epoch = int.from_bytes(table.get_item(Key={"key": "EpochCount"}).get('Item')["value"].value, "big")
        except Exception as e:
            print(e)
            epoch = -1
        return epoch

if __name__ == "__main__":
    db = Database()
    print(db)
