.. _kvs_flash:

kvs_flash
###########

Overview
********

A simple sample that shows how to use the key value store subsystem.

Building and Running
********************

This application can be built and executed on QEMU as follows:

.. zephyr-app-commands::
   :zephyr-app: sample
   :host-os: unix
   :board: qemu_x86
   :goals: run
   :compact:

To build for another board, change "qemu_x86" above to that board's name.

Sample Output
=============

.. code-block:: console

    KVS_SAMPLE...

Exit QEMU by pressing :kbd:`CTRL+A` :kbd:`x`.
