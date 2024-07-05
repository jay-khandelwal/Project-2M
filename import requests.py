import requests
import pandas as pd

HEADERS = {
    'Authorization': f'Bearer {API_TOKEN}',
    'Content-Type': 'application/json'
}

# Function to create a batch of shapes (nodes) in Miro
def create_shapes(board_id, nodes):
    url = f'https://api.miro.com/v2/boards/{board_id}/shapes'
    responses = []
    print(f"Creating {len(nodes)} shapes...")
    for idx, node in enumerate(nodes):
        payload = {
            "data": {
                "content": node['content'],
                "shape": node['shape']
            },
            "style": {
                "borderColor": node['borderColor'],
                "borderOpacity": "1.0",
                "borderStyle": "normal",
                "borderWidth": "1",
                "color": "#1a1a1a",
                "fillColor": node['fillColor'],
                "fillOpacity": "1.0",
                "fontFamily": "arial",
                "fontSize": "10",
                "textAlign": "center",
                "textAlignVertical": "middle"
            },
            "position": {
                "x": node['x'],
                "y": node['y']
            },
            "geometry": {
                "height": 60,
                "rotation": 0,
                "width": 100
            }
        }
        response = requests.post(url, headers=HEADERS, json=payload)
        if response.status_code == 201:
            responses.append(response.json())
            print(f"Shape {idx+1}/{len(nodes)} created successfully: {node['content']}")
        else:
            print(f"Error creating shape {idx+1}/{len(nodes)}: {response.status_code}, {response.text}")
    return responses

# Function to create a batch of connectors (edges) in Miro
def create_connectors(board_id, connectors):
    url = f'https://api.miro.com/v2/boards/{board_id}/connectors'
    print(f"Creating {len(connectors)} connectors...")
    for idx, connector in enumerate(connectors):
        payload = {
            "startItem": {
                "id": connector['start_id'],
                # "position": {"x": "50%", "y": "0%"},
                "snapTo": "auto"
            },
            "endItem": {
                "id": connector['end_id'],
                # "position": {"x": "50%", "y": "0%"},
                "snapTo": "auto"
            },
            "shape": "straight",
            "style": {
                "color": "#9510ac",
                "endStrokeCap": "none",
                "fontSize": "15",
                "startStrokeCap": "none",
                "strokeColor": "#2d9bf0",
                "strokeStyle": "normal",
                "strokeWidth": "2.0",
                "textOrientation": "horizontal"
            }
        }
        response = requests.post(url, headers=HEADERS, json=payload)
        if response.status_code == 200:
            print(f"Connector {idx+1}/{len(connectors)} created successfully")
        else:
            print(f"Error creating connector {idx+1}/{len(connectors)}: {response.status_code}, {response.text}")
    return "Connectors created successfully"

# Create graph from DataFrame
def create_graph_in_miro(board_id, df):
    nodes = {}
    shapes_payload = []
    connectors_payload = []
    x, y = 0, 0
    x_step, y_step = 200, 100

    print("Preparing shapes and connectors...")
    for index, row in df.iterrows():
        referer = row['Referer']
        full_path = row['full_path']

        if referer not in nodes:
            node = {
                'content': referer,
                'shape': 'trapezoid',
                'borderColor': '#000000',
                'fillColor': '#ADD8E6',
                'x': x,
                'y': y
            }
            nodes[referer] = len(shapes_payload)
            shapes_payload.append(node)
            x += x_step

        if full_path not in nodes:
            node = {
                'content': full_path,
                'shape': 'rectangle',
                'borderColor': '#000000',
                'fillColor': '#ADD8E6',
                'x': x,
                'y': y
            }
            nodes[full_path] = len(shapes_payload)
            shapes_payload.append(node)
            y += y_step

    print("Shapes and connectors prepared.")
    shapes_response = create_shapes(board_id, shapes_payload)

    print("Shape created successfully.")

    if shapes_response:
        print("starting for connector.")
        widget_ids = [widget['id'] for widget in shapes_response]
        for referer, full_path in zip(df['Referer'], df['full_path']):
            start_widget_id = widget_ids[nodes[referer]]
            end_widget_id = widget_ids[nodes[full_path]]
            connector = {
                'start_id': start_widget_id,
                'end_id': end_widget_id
            }
            connectors_payload.append(connector)
        print("connectors_payload len:-", len(connectors_payload))
        create_connectors(board_id, connectors_payload)

# Generate a random DataFrame with 500 nodes for demonstration
num_nodes = 10  # Adjust as needed for 500-1000 nodes
data = {
    'Referer': [f'Node_{i}' for i in range(num_nodes)],
    'full_path': [f'Node_{i+1}' for i in range(num_nodes-1)] + ['Node_0']  # Ensure it's within the range
}
df = pd.DataFrame(data)

# Create the graph in Miro
create_graph_in_miro(BOARD_ID, df)
