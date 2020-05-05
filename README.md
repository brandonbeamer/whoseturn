Copyright © 2020 Brandon Beamer

Overview
========

Whose Turn Is It is a django-based web app that helps groups who share responsibilities to keep track of, well, whose turn it is. This project was developed out of a real need for my partner and I to keep track of whose turn it was to buy dinner—something we, amazing, had real difficulty keeping track of.

Implementation
==============
Django/Python

Features
========
  - Built-in user management (e.g. login/register/password reset emails/etc.)
  - Support user-specific time zones
  - Creating tasks and inviting others to it via email
  - Recording comments on completed turns
  - Viewing shared task history
  - Responsive layout looks great on all screen sizes

How it Works
============

Whose Turn Is It maintains a history of when people took their turn in a group task. When new people are invited to the group, their turn count is set to that of the group leader. In deciding whose turn it is, the system chooses the unique user with the least turns taken. If there is a tie for least turns taken, it breaks the tie by choosing the user who has gone least recently.
