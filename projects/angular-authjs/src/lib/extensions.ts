export class NotFoundException extends Error {
  public readonly code: string;

  constructor(
    code: string = 'NOT_FOUND',
    message: string = 'Resource not found'
  ) {
    super(message);
    this.name = 'NotFoundException';
    this.code = code;
    Object.setPrototypeOf(this, NotFoundException.prototype);
  }
}

export class InvalidArgumentException extends Error {
  public readonly code: string;

  constructor(
    code: string = 'INVALID_ARGUMENT',
    message: string = 'Invalid argument provided'
  ) {
    super(message);
    this.name = 'InvalidArgumentException';
    this.code = code;
    Object.setPrototypeOf(this, InvalidArgumentException.prototype);
  }
}
