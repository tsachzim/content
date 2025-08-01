This pack includes XSIAM content.

## How configure Rsyslog on FireEye

1. Log into the FireEye appliance with an administrator account.
2. Click **Settings**.
3. Click **Notifications**.
4. Click **rsyslog**.
5. Check the *Event type* checkbox.
6. Make sure *Rsyslog* settings are:
   - Default format: CEF
   - Default delivery: Per event
   - Default send as: Alert

- Pay attention: Timestamp parsing is supported for the **rt** field, containing Epoch (UNIX) time.

## Collect Events from Vendor

In order to use the collector, you can use one of the following options to collect events from the vendor:

- [Broker VM](#broker-vm)

In either option, you will need to configure the vendor and product for this specific collector.

### Broker VM

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).\
You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Right-click, and select **Syslog Collector** > **Configure**.
3. When configuring the Syslog Collector, set:
    - vendor as FireEye
    - product as mps
