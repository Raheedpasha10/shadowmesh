| policy | sessions | avg_reward | top_action | action_breakdown |
|---|---:|---:|---|---|
| do_nothing | 10 | 20.10 | do_nothing | do_nothing:10 |
| show_fake_credentials_after_successful_session | 10 | 24.60 | show_fake_credentials | do_nothing:1, show_fake_credentials:9 |
| ppo | 10 | 22.90 | show_fake_file | open_fake_port:1, show_fake_credentials:1, show_fake_file:8 |
