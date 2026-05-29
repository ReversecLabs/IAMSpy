import logging
import os
from typing import List, Optional
import typer
from iamspy.model import Model
from pathlib import Path
from iamspy.log_config import build_logger

DEFAULT_MODEL_FILENAME = "model.json"


app = typer.Typer()


@app.command()
def load_gaad(gaad: str = typer.Argument(...), model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f")):
    m = Model()
    if Path(model).is_file():
        m.load_model(model)
    m.load_gaad(gaad)
    m.save(model)


@app.command()
def load_gaads(folder: str = typer.Argument(...), model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f")):
    m = Model()
    if Path(model).is_file():
        m.load_model(model)
    m.load_gaads(folder)
    m.save(model)


@app.command()
def load_resources(resources: str = typer.Argument(...), model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f")):
    m = Model()
    if Path(model).is_file():
        m.load_model(model)
    m.load_resource_policies(resources)
    m.save(model)


@app.command()
def load_scps(scps: str = typer.Argument(...), model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f")):
    m = Model()
    if Path(model).is_file():
        m.load_model(model)
    m.load_scps(scps)
    m.save(model)


@app.command()
def can_i(
    source_arn: str = typer.Argument(...),
    action: str = typer.Argument(...),
    resource: str = typer.Argument(...),
    conditions: List[str] = typer.Option([], "-c", help="List of conditions as key=value string pairs"),
    condition_file: Optional[str] = typer.Option(
        None, "-C", help="File of conditions to load following IAM condition syntax"
    ),
    strict_conditions: bool = typer.Option(
        False, help="Whether to require conditions to be passed in for any IAM condition checks"
    ),
    model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f"),
):
    """
    Pulls out applicable policies, runs can_i
    """
    m = Model()
    if Path(model).is_file():
        m.load_model(model)

    print(m.can_i(source_arn, action, resource, conditions, condition_file, strict_conditions))


@app.command()
def who_can(
    action: str = typer.Argument(...),
    resource: str = typer.Argument(...),
    conditions: List[str] = typer.Option([], "-c", help="List of conditions as key=value string pairs"),
    condition_file: Optional[str] = typer.Option(
        None, "-C", help="File of conditions to load following IAM condition syntax"
    ),
    strict_conditions: bool = typer.Option(
        False, help="Whether to require conditions to be passed in for any IAM condition checks"
    ),
    workers: int = typer.Option(os.cpu_count(), "-w", help="Number of parallel worker processes"),
    model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f"),
):
    """
    Pulls out applicable policies, runs who_can
    """
    m = Model()
    if Path(model).is_file():
        m.load_model(model)

    for x in m.who_can(action, resource, conditions, condition_file, strict_conditions, workers):
        print(x)


@app.command()
def which_can_i(
    source_arn: str = typer.Argument(...),
    action: str = typer.Argument(...),
    resources_files: str = typer.Argument(...),
    conditions: List[str] = typer.Option([], "-c", help="List of conditions as key=value string pairs"),
    condition_file: Optional[str] = typer.Option(
        None, "-C", help="File of conditions to load following IAM condition syntax"
    ),
    strict_conditions: bool = typer.Option(
        False, help="Whether to require conditions to be passed in for any IAM condition checks"
    ),
    model: str = typer.Option("model.smt2", "-f"),
):
    """
    Pulls out applicable policies, runs which_can_i
    """
    m = Model()
    if Path(model).is_file():
        m.load_model(model)

    with open(resources_files) as fs:
        resources = fs.read().strip().split("\n")

    for x in m.which_can_i(source_arn, action, resources, conditions, condition_file, strict_conditions):
        print(x)


@app.command()
def who_can_batch_resource(
    action: str = typer.Argument(...),
    resources_file: str = typer.Argument(...),
    conditions: List[str] = typer.Option([], "-c", help="List of conditions as key=value string pairs"),
    condition_file: Optional[str] = typer.Option(
        None, "-C", help="File of conditions to load following IAM condition syntax"
    ),
    strict_conditions: bool = typer.Option(
        False, help="Whether to require conditions to be passed in for any IAM condition checks"
    ),
    workers: int = typer.Option(os.cpu_count(), "-w", help="Number of parallel worker processes"),
    model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f"),
):
    """
    Pulls out applicable policies, runs who_can
    """
    m = Model()
    if Path(model).is_file():
        m.load_model(model)

    with open(resources_file) as fs:
        resources = fs.read().strip().split("\n")

    for source, resource in m.who_can_batch_resource(action, resources, conditions, condition_file, strict_conditions, workers):
        print(f"{source} can perform {action} on {resource}")


@app.command()
def supports_external(
    model: str = typer.Option(DEFAULT_MODEL_FILENAME, "-f"),
):
    """
    Pulls out resources that allow access from identities not within the model
    """
    m = Model()
    if Path(model).is_file():
        m.load_model(model)

    print(m.supports_external(action, resource))


@app.callback()
def main(verbose: int = typer.Option(0, "--verbose", "-v", count=True)):
    """
    CLI interface for iamspy, the AWS IAM analysis framework
    """
    verbosity_levels = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
    }
    build_logger(verbosity_levels[verbose])
