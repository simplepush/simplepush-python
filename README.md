Python module to send push notifications via [Simplepush](https://simplepush.io/).

# Installation
```bash
pip3 install simplepush
```

# Examples
All examples can be made asynchronous by using `async_send` instead of `send`.

* Send a push notification to the Simplepush key `YourKey`:
```python
import simplepush
simplepush.send(key='YourKey', title='Notification title', message='Notification message')
```

* Send a push notification with actions and a callback function that will print the selected action:
```python
import simplepush

def callback(action_selected, action_selected_at, action_delivered_at, feedback_id):
  print(action_selected)

simplepush.send(key='YourKey', title='Title', message='Actionable notification', actions=['yes', 'no', 'maybe'], feedback_callback=callback)
```

* Send an end-to-end encrypted push notification with actions and a callback function that will print the selected action and times out after 120 seconds:
```python
import simplepush

def callback(action_selected, action_selected_at, action_delivered_at, feedback_id):
  print(action_selected)

simplepush.send(key='YourKey', password='password', salt='salt', message='Actionable notification', actions=['yes', 'no', 'maybe'], feedback_callback=callback, feedback_callback_timeout=120)
```

* Send an end-to-end encrypted push notification with an image and a video file:
```python
import simplepush
simplepush.send(key='YourKey', message='Attachments', password='password', salt='salt', attachments=['https://upload.wikimedia.org/wikipedia/commons/e/ee/Sample_abc.jpg', {'video': 'http://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4', 'thumbnail': 'http://commondatastorage.googleapis.com/gtv-videos-bucket/sample/images/ForBiggerEscapes.jpg'}])
```