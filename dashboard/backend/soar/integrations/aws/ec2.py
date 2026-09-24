"""EC2 DescribeInstances."""
from .paging import collect


def describe_instances(session, instance_id=None):
    filters = [{"Name": "instance-id", "Values": [instance_id]}] if instance_id else []
    reservations = collect(session.client("ec2"), "describe_instances", "Reservations",
                           **({"Filters": filters} if filters else {}))
    return [instance for reservation in reservations for instance in reservation.get("Instances", [])]
